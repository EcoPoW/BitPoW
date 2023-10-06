
import sys
import os
import time
import hashlib
import multiprocessing
import json
import types
import pprint
import argparse
# import threading
# import curses

# import eth_hash.auto
import web3
import eth_account
import eth_abi
import requests
import hexbytes

import tornado.ioloop
import tornado.gen
import tornado.websocket
import tornado.autoreload

import rocksdb

import contracts
import state
import eth_tx
import console
import setting


def pow(conn):
    start = 0
    try:
        sleep = True
        while True:
            if conn.poll():
                m = conn.recv()
                if m[0] == 'START':
                    console.log('start', m)
                    block_hash = m[1]
                    start = m[2]
                    target = m[3]
                    sleep = False
                elif m[0] == 'STOP':
                    sleep = True

            if sleep:
                time.sleep(5)
                # print('sleep')
                continue

            # t0 = time.time()
            nonce = start
            for nonce in range(start, start+10000000):
                if nonce % 100000 == 0:
                    print(nonce)
                pow_hash= hashlib.sha256(block_hash + str(nonce).encode('utf8')).digest()
                difficulty = int.from_bytes(pow_hash, byteorder='big', signed=False)
                if difficulty <= target:
                    console.log(pow_hash.hex(), nonce)
                    conn.send(['FOUND', block_hash, nonce, difficulty])
                    sleep = True
                    break
            else:
                conn.send(['DONE', block_hash, start, start+10000000, target])
                sleep = True

    except:
        pass


def pos(parent_block_hash, parent_block_number):
    it = db.iteritems()
    contract_address = '0x0000000000000000000000000000000000000002'
    results = {}
    it.seek(('globalstate_%s_' % contract_address).encode('utf8'))
    for k, v in it:
        # print('GetStateSubchainsHandler', k.decode('utf8').split('_'), v)
        if not k.startswith(('globalstate_%s_' % contract_address).encode('utf8')):
            break

        ks = k.decode('utf8').split('_')
        no = setting.REVERSED_NO - int(ks[4])
        addr = ks[3]
        height, _ = results.get(addr, (0, None))
        print(k, v)
        if no > height:
            results[addr] = no, json.loads(v)
        # if block_height and setting.REVERSED_NO - reversed_no != no:
        #     continue
    console.log(results)

    total = 0
    for k, v in results.items():
        total += v[1][0]
    console.log(total)

    rank_addr = {}
    ranks = []
    user_rank = 0
    for k, v in results.items():
        pos_data = {
            'height': parent_block_number + 1,
            'parent': parent_block_hash,
            'address': k,
            'total': total,
        }
        pos_hash = hashlib.sha256(json.dumps(pos_data, sort_keys=True).encode('utf8')).digest()
        staking_value = v[1][0]
        staking_coinage = parent_block_number + 1 - v[1][1]
        print(staking_value, staking_coinage)
        rank = int.from_bytes(pos_hash, byteorder='big', signed=False) // (staking_value * staking_coinage)
        print(k, rank)
        rank_addr.setdefault(rank, []).append(k)
        ranks.append(rank)

        if k == user_addr:
            user_rank = rank

    ranks.sort()
    print(user_addr, user_rank)
    print(ranks)
    if user_rank:
        print(ranks.index(user_rank))

    return user_rank

def new_block(parent_block_hash, parent_block_number):
    txbody = []
    statebody = {}
    state.block_number = parent_block_number + 1

    req = requests.get(API_ENDPOINT+'/get_pool_subchains')
    pool_subchains = req.json()
    console.log('get_pool_subchains', req.json())
    req = requests.get(API_ENDPOINT+'/get_state_subchains?addrs=%s&height=%s' % (','.join(pool_subchains.keys()), parent_block_number))
    console.log('get_state_subchains', req.text)
    state_subchains = req.json()

    for addr in pool_subchains:
        #console.log('current_mining', self.current_mining)
        console.log('get_pool_subchains addr', addr, pool_subchains[addr.lower()])
        to_no, to_hash = pool_subchains[addr.lower()]
        console.log('get_state_subchains addr', state_subchains[addr.lower()])
        from_no = 0
        if state_subchains[addr.lower()]:
            from_no = state_subchains[addr.lower()]['height']
        console.log(API_ENDPOINT+'/get_pool_blocks?addr=%s&from_no=%s&to_no=%s&to_hash=%s' % (addr, from_no, to_no, to_hash))
        req = requests.get(API_ENDPOINT+'/get_pool_blocks?addr=%s&from_no=%s&to_no=%s&to_hash=%s' % (addr, from_no, to_no, to_hash))
        txblocks = req.json()['blocks']
        txblocks.reverse()
        console.log(txblocks)
        last_tx_hash = None
        last_tx_height= 0
        for txblock in txblocks:
            #pprint.pprint(txblock)
            tx_list = txblock[4]
            if len(tx_list) == 8:
                tx_to = tx_list[5]
                tx_data = tx_list[7]
            else:
                tx_to = tx_list[4]
                tx_data = tx_list[6]
            tx_signature_hex = txblock[5]
            tx_signature_obj = eth_account.Account._keys.Signature(signature_bytes=hexbytes.HexBytes(tx_signature_hex))
            vrs = tx_signature_obj.vrs

            tx_hash = eth_tx.hash_of_eth_tx_list(tx_list)
            tx_from = eth_account.Account._recover_hash(tx_hash, vrs=vrs)
            #print('tx_from', tx_from)

            contracts.vm_map[tx_to].global_vars['_block_number'] = state.block_number
            contracts.vm_map[tx_to].global_vars['_call'] = state.call
            contracts.vm_map[tx_to].global_vars['_get'] = state.get
            contracts.vm_map[tx_to].global_vars['_put'] = state.put
            contracts.vm_map[tx_to].global_vars['_sender'] = tx_from.lower()
            state.contract_address = tx_to
            contracts.vm_map[tx_to].global_vars['_self'] = state.contract_address

            func_sig = tx_data[:8]
            # print(interface_map[func_sig], tx_data)
            func_params_data = tx_data[8:]
            func_params_type = contracts.params_map[tx_to][contracts.interface_map[tx_to][func_sig].__name__]
            console.log(func_params_type)
            console.log(func_params_data)
            func_params = eth_abi.decode(func_params_type, hexbytes.HexBytes(func_params_data))
            console.log(func_params)

            # result = interface_map[func_sig](*func_params)
            contracts.vm_map[tx_to].run(func_params, contracts.interface_map[tx_to][func_sig].__name__)
            if len(tx_list) == 8:
                last_tx_height = tx_list[1]
            else:
                last_tx_height = tx_list[0]
            last_tx_hash = txblock[0]

        if txblocks:
            txbody.append([addr, last_tx_height, last_tx_hash])

    console.log(txbody)
    txbody_json = json.dumps(txbody)
    statebody = state.dump()
    console.log(statebody)
    statebody_json = json.dumps(statebody, sort_keys=True)

    txbody_hash = hashlib.sha256(txbody_json.encode('utf8')).hexdigest()
    statebody_hash = hashlib.sha256(statebody_json.encode('utf8')).hexdigest()
    console.log(txbody_hash)
    console.log(statebody_hash)

    header_data = {
        'txbody_hash': txbody_hash,
        'statebody_hash': statebody_hash,
        'height': parent_block_number + 1,
        'difficulty': 2**254,
        'parent': parent_block_hash,
        'address': user_addr,
        'timestamp': 0,
    }

    return header_data, txbody_json, statebody_json


class MiningClient:
    def __init__(self, url, timeout):
        self.url = url
        self.timeout = timeout
        self.ws = None
        self.current_mining = None
        self.next_mining = {}
        self.header_data = None

        self.connect()
        tornado.ioloop.PeriodicCallback(self.keep_alive, 3000).start()
        tornado.ioloop.PeriodicCallback(self.pos, setting.BLOCK_INTERVAL_SECONDS*1000).start()
        tornado.ioloop.PeriodicCallback(self.poll, 100).start()

    @tornado.gen.coroutine
    def connect(self):
        console.log("trying to connect")
        try:
            self.ws = yield tornado.websocket.websocket_connect(self.url)
        except Exception:
            console.log("connection error")
        else:
            console.log("connected")
            self.run()

    @tornado.gen.coroutine
    def run(self):
        while True:
            msg = yield self.ws.read_message()
            if msg is None:
                console.log("connection closed")
                self.ws = None
                break

            console.log(msg)
            seq = json.loads(msg)
            if seq[0] == 'NEW_CHAIN_TXBODY':
                pass

            elif seq[0] == 'NEW_CHAIN_STATEBODY':
                pass

            elif seq[0] == 'NEW_CHAIN_HEADER':
                parent_block_hash = seq[1]
                parent_block_number = seq[2]['height']
                console.log(parent_block_hash, parent_block_number)

                #state.merge(block_hash, state.pending_state)
                # state.pending_state = {}
                #self.current_mining = None

                if setting.POW:
                    # stop if mining
                    req = requests.get(API_ENDPOINT+'/get_chain_latest')
                    console.log('get_chain_latest', req.text)
                    obj = req.json()
                    if obj['height'] == 0:
                        parent_block_hash = '0'*64
                    else:
                        parent_block_hash = obj['blockhashes'][0]
                    parent_block_number = obj['height']

                    self.header_data, self.txbody_json, self.statebody_json = new_block(parent_block_hash, parent_block_number)
                    block_hash_obj = hashlib.sha256(json.dumps(self.header_data, sort_keys=True).encode('utf8'))
                    block_hash = block_hash_obj.hexdigest()
                    console.log(block_hash)
                    conn.send(['START', block_hash_obj.digest(), 0, 2**230])

            elif seq[0] == 'NEW_SUBCHAIN_BLOCK':
                tx_list = seq[5]
                if len(tx_list) == 8:
                    count = tx_list[1]
                else:
                    count = tx_list[0]
                signature = seq[6]
                eth_tx_hash = eth_tx.hash_of_eth_tx_list(tx_list)
                signature_obj = eth_account.Account._keys.Signature(bytes.fromhex(signature[2:]))
                pubkey = signature_obj.recover_public_key_from_msg_hash(eth_tx_hash)
                sender = pubkey.to_checksum_address()
                console.log('sender', sender, 'count', count)
                console.log('tx_list', tx_list)

                txs = self.next_mining.setdefault(sender, [])
                txs.append(tx_list)
                #statebody = {}
                #print('txs', txs)
                console.log('current_mining', self.current_mining)
                if not self.current_mining:
                    self.current_mining = self.next_mining
                    self.next_mining = {}
                    console.log('current_mining', self.current_mining)

                    for addr in self.current_mining:
                        #print('current_mining', current_mining)
                        console.log('current_mining[addr]', addr, self.current_mining[addr])

                    if setting.POW:
                        req = requests.get(API_ENDPOINT+'/get_chain_latest')
                        console.log('get_chain_latest', req.text)
                        obj = req.json()
                        if obj['height'] == 0:
                            parent_block_hash = '0'*64
                        else:
                            parent_block_hash = obj['blockhashes'][0]
                        parent_block_number = obj['height']

                        self.header_data, self.txbody_json, self.statebody_json = new_block(parent_block_hash, parent_block_number)
                        block_hash_obj = hashlib.sha256(json.dumps(self.header_data, sort_keys=True).encode('utf8'))
                        block_hash = block_hash_obj.hexdigest()
                        console.log(block_hash)
                        conn.send(['START', block_hash_obj.digest(), 0, 2**230])


    def keep_alive(self):
        if self.ws is None:
            self.connect()
        else:
            self.ws.write_message('["KEEP_ALIVE"]')

    def poll(self):
        for conn in cs:
            if conn.poll(0.1):
                m = conn.recv()
                if m[0] == 'DONE':
                    # continue
                    console.log(m)
                    block_hash_bytes = m[1]
                    end = m[3]
                    target = m[4]
                    console.log(block_hash_bytes.hex())
                    conn.send(['START', block_hash_bytes, end, target])

                elif m[0] == 'FOUND':
                    # submit to chain
                    console.log(m)
                    block_hash = m[1].hex()
                    nonce = m[2]
                    difficulty = m[3]
                    msgid = hashlib.sha256(('%s_%s_%s' % (block_hash, self.header_data['height'], self.txbody_json)).encode('utf8')).hexdigest()
                    message = ['NEW_CHAIN_TXBODY', block_hash, self.header_data['height'], self.txbody_json, msgid]
                    self.ws.write_message(json.dumps(message))
                    msgid = hashlib.sha256(('%s_%s_%s' % (block_hash, self.header_data['height'], self.statebody_json)).encode('utf8')).hexdigest()
                    message = ['NEW_CHAIN_STATEBODY', block_hash, self.header_data['height'], self.statebody_json, msgid]
                    self.ws.write_message(json.dumps(message))
                    message = ['NEW_CHAIN_HEADER', block_hash, self.header_data, nonce, difficulty]
                    self.ws.write_message(json.dumps(message))

                    statebody = state.dump()
                    console.log(statebody)
                    state.merge(block_hash, statebody)
                    # state.pending_state = {}
                    self.current_mining = None

    def pos(self):
        if setting.POW:
            return

        self.current_mining = self.next_mining
        self.next_mining = {}
        console.log('current_mining', self.current_mining)

        for addr in self.current_mining:
            #print('current_mining', current_mining)
            console.log('current_mining[addr]', addr, self.current_mining[addr])

        req = requests.get(API_ENDPOINT+'/get_chain_latest')
        console.log('get_chain_latest', req.text)
        obj = req.json()
        if obj['height'] == 0:
            parent_block_hash = '0'*64
        else:
            parent_block_hash = obj['blockhashes'][0]
        parent_block_number = obj['height']

        self.header_data, self.txbody_json, self.statebody_json = new_block(parent_block_hash, parent_block_number)
        block_hash_obj = hashlib.sha256(json.dumps(self.header_data, sort_keys=True).encode('utf8'))
        block_hash = block_hash_obj.hexdigest()
        console.log(block_hash)

        statebody = state.dump()
        console.log(statebody)
        state.merge(block_hash, statebody)
        # state.pending_state = {}

        user_rank = pos(parent_block_hash, parent_block_number)
        console.log(user_rank)
        msgid = hashlib.sha256(('%s_%s_%s' % (block_hash, self.header_data['height'], self.txbody_json)).encode('utf8')).hexdigest()
        message = ['NEW_CHAIN_TXBODY', block_hash, self.header_data['height'], self.txbody_json, msgid]
        self.ws.write_message(json.dumps(message))
        msgid = hashlib.sha256(('%s_%s_%s' % (block_hash, self.header_data['height'], self.statebody_json)).encode('utf8')).hexdigest()
        message = ['NEW_CHAIN_STATEBODY', block_hash, self.header_data['height'], self.statebody_json, msgid]
        self.ws.write_message(json.dumps(message))
        message = ['NEW_CHAIN_HEADER', block_hash, self.header_data, -1, user_rank]
        self.ws.write_message(json.dumps(message))

ps = []
cs = []

API_ENDPOINT = 'http://127.0.0.1:9001'
WS_ENDPOINT = 'ws://127.0.0.1:9001'


if __name__ == "__main__":
    if not os.path.exists('users'):
        os.makedirs('users')
    db = rocksdb.DB('users/consensus.db', rocksdb.Options(create_if_missing=True))
    state.init_state(db)

    try:
        with open('users/consensus.json', 'r') as f:
            config_obj = json.loads(f.read())
            if 'api' in config_obj:
                API_ENDPOINT = config_obj['api']
            if 'ws' in config_obj:
                WS_ENDPOINT = config_obj['ws']
            if 'key' in config_obj:
                user_addr = config_obj['key']
    except:
        config_obj = {}

    parser = argparse.ArgumentParser(description='consensus.py [--api=http://127.0.0.1:9001] [--ws=ws://127.0.0.1:9001] [--key=user/keyfile.json]')
    parser.add_argument('--key')
    parser.add_argument('--api')
    parser.add_argument('--ws')
    args = parser.parse_args()
    if args.api:
        API_ENDPOINT = args.api
        config_obj['api'] = args.api
    if args.ws:
        WS_ENDPOINT = args.ws
        config_obj['ws'] = args.ws
    if args.key:
        user_addr = args.key
        config_obj['key'] = args.key
    with open('users/consensus.json', 'w') as f:
        f.write(json.dumps(config_obj))
    pprint.pprint(config_obj)
 
    conn, child_conn = multiprocessing.Pipe()
    process = multiprocessing.Process(target=pow, args=(child_conn,))
    ps.append(process)
    cs.append(conn)
    process.start()
    client = MiningClient(WS_ENDPOINT+'/miner', 5)

    tornado.autoreload.start()
    tornado.ioloop.IOLoop.instance().start()
