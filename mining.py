
import sys
import os
import time
import hashlib
import multiprocessing
import json
import types
import pprint
# import threading
# import curses

# import eth_hash.auto
import web3
import eth_account
import eth_utils
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


if not os.path.exists('miners'):
    os.makedirs('miners')
db = rocksdb.DB('miners/mining.db', rocksdb.Options(create_if_missing=True))

state.init_state(db)


def pow(conn):
    start = 0
    try:
        d = 6
        sleep = True
        while True:
            if conn.poll():
                m = conn.recv()
                if m[0] == 'START':
                    console.log('start', m)
                    block_hash = m[1]
                    start = m[2]
                    #difficulty = m[3]
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
                h = hashlib.sha256(block_hash + str(nonce).encode('utf8')).hexdigest()
                if h.startswith('0'*d):
                    console.log(h, nonce)
                    conn.send(['FOUND', block_hash, nonce])
                    sleep = True
                    break
            else:
                conn.send(['DONE', block_hash, start, start+10000000])
                sleep = True

    except:
        pass


class MiningClient:
    def __init__(self, url, timeout):
        self.url = url
        self.timeout = timeout
        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.ws = None
        self.current_mining = None
        self.next_mining = {}
        self.header_data = None

        self.connect()
        tornado.ioloop.PeriodicCallback(self.keep_alive, 20000).start()
        tornado.ioloop.PeriodicCallback(self.poll, 100).start()
        self.ioloop.start()

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
            else:
                #console.log(msg)
                seq = json.loads(msg)
                if seq[0] == '_NEW_CHAIN_BLOCK':
                    # next_mining.append(message['name'])
                    if not self.current_mining:
                        self.current_mining = self.next_mining
                        self.next_mining = {}
                        commitment = hashlib.sha256(json.dumps(self.current_mining).encode('utf8')).digest()
                        conn.send(['START', commitment, 0])

                elif seq[0] == 'NEW_SUBCHAIN_BLOCK':
                    data = seq[5]
                    count = data[0]
                    signature = seq[6]
                    eth_tx_hash = eth_tx.hash_of_eth_tx_list(data)
                    signature_obj = eth_account.Account._keys.Signature(bytes.fromhex(signature[2:]))
                    pubkey = signature_obj.recover_public_key_from_msg_hash(eth_tx_hash)
                    sender = pubkey.to_checksum_address()
                    console.log('sender', sender, 'count', count)
                    console.log('data', data)

                    txs = self.next_mining.setdefault(sender, [])
                    txs.append(data)
                    txbody = []
                    #statebody = {}
                    #print('txs', txs)
                    console.log('current_mining', self.current_mining)
                    if not self.current_mining:
                        self.current_mining = self.next_mining
                        self.next_mining = {}
                        console.log('current_mining', self.current_mining)

                        req = requests.get('http://127.0.0.1:9001/get_chain_latest')
                        console.log('get_chain_latest', req.text)
                        obj = req.json()
                        if obj['height'] == 0:
                            parent_hash = '0'*64
                        else:
                            parent_hash = obj['blockhashes'][0]
                        block_number = obj['height']

                        _state = state.get_state()
                        _state.block_number = block_number + 1

                        for addr in self.current_mining:
                            #print('current_mining', current_mining)
                            console.log('current_mining[addr]', addr, self.current_mining[addr])

                        req = requests.get('http://127.0.0.1:9001/get_pool_subchains')
                        pool_subchains = req.json()
                        #console.log('get_pool_subchains', req.json())
                        req = requests.get('http://127.0.0.1:9001/get_state_subchains?addrs=%s&height=%s' % (','.join(pool_subchains.keys()), block_number))
                        console.log('get_state_subchains', req.text)
                        state_subchains = req.json()

                        for addr in pool_subchains:
                            #console.log('current_mining', self.current_mining)
                            console.log('get_pool_subchains addr', addr, pool_subchains[addr])
                            to_no, to_hash = pool_subchains[addr]
                            console.log('get_state_subchains addr', state_subchains[addr])
                            from_no = 0
                            if state_subchains[addr]:
                                from_no = state_subchains[addr]['height']
                            req = requests.get('http://127.0.0.1:9001/get_pool_blocks?addr=%s&from_no=%s&to_no=%s&to_hash=%s' % (addr, from_no, to_no, to_hash))
                            txblocks = req.json()['blocks']
                            txblocks.reverse()
                            last_tx_hash = None
                            last_tx_height= None
                            for txblock in txblocks:
                                pprint.pprint(txblock)
                                tx_list = txblock[4]
                                tx_to = tx_list[4]
                                tx_data = tx_list[6]
                                tx_signature_hex = txblock[5]
                                tx_signature_obj = eth_account.Account._keys.Signature(signature_bytes=hexbytes.HexBytes(tx_signature_hex))
                                vrs = tx_signature_obj.vrs

                                tx_hash = eth_tx.hash_of_eth_tx_list(tx_list)
                                tx_from = eth_account.Account._recover_hash(tx_hash, vrs=vrs)
                                #print('tx_from', tx_from)

                                contracts.vm_map[tx_to].global_vars['_block_number'] = _state.block_number
                                contracts.vm_map[tx_to].global_vars['_call'] = state.call
                                contracts.vm_map[tx_to].global_vars['_state'] = _state
                                contracts.vm_map[tx_to].global_vars['_sender'] = tx_from
                                _state.contract_address = tx_to
                                contracts.vm_map[tx_to].global_vars['_self'] = _state.contract_address

                                func_sig = tx_data[:10]
                                # print(interface_map[func_sig], tx_data)
                                func_params_data = tx_data[10:]
                                func_params = [func_params_data[i:i+64] for i in range(0, len(func_params_data)-2, 64)]
                                #print('func', interface_map[func_sig].__name__, func_params)
                                type_params = []
                                for k, v in zip(contracts.type_map[tx_to][contracts.interface_map[tx_to][func_sig].__name__], func_params):
                                    # print('type', k, v)
                                    if k == 'address':
                                        type_params.append(web3.Web3.to_checksum_address('0x'+v[24:]))
                                    elif k == 'uint256':
                                        type_params.append(web3.Web3.to_int(hexstr=v))

                                # result = interface_map[func_sig](*func_params)
                                contracts.vm_map[tx_to].run(type_params, contracts.interface_map[tx_to][func_sig].__name__)
                                last_tx_height = tx_list[0]
                                last_tx_hash = txblock[0]
                            txbody.append([addr, last_tx_height, last_tx_hash])

                        console.log(txbody)
                        console.log(state.pending_state)
                        self.txbody_json = json.dumps(txbody)
                        self.statebody_json = json.dumps(state.pending_state, sort_keys=True)
                        txbody_hash = hashlib.sha256(self.txbody_json.encode('utf8')).hexdigest()
                        statebody_hash = hashlib.sha256(self.statebody_json.encode('utf8')).hexdigest()
                        console.log(txbody_hash)
                        console.log(statebody_hash)

                        self.header_data = {
                            'txbody_hash': txbody_hash,
                            'statebody_hash': statebody_hash,
                            'height': block_number + 1,
                            'difficulty': 2**254,
                            'parent': parent_hash,
                            'address': '0x'+'0'*40,
                            'timestamp': 0,
                        }
                        block_hash = hashlib.sha256(json.dumps(self.header_data, sort_keys=True).encode('utf8')).digest()
                        console.log(block_hash)
                        conn.send(['START', block_hash, 0])

                    else:
                        pass

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
                    block_hash = m[1]
                    end = m[3]
                    console.log(block_hash)
                    conn.send(['START', block_hash, end])

                elif m[0] == 'FOUND':
                    # submit to chain
                    console.log(m)
                    block_hash = m[1].hex()
                    nonce = m[2]
                    message = ['NEW_CHAIN_TXBODY', block_hash, self.header_data['height'], self.txbody_json]
                    self.ws.write_message(json.dumps(message))
                    message = ['NEW_CHAIN_STATEBODY', block_hash, self.header_data['height'], self.statebody_json]
                    self.ws.write_message(json.dumps(message))
                    message = ['NEW_CHAIN_HEADER', block_hash, self.header_data, nonce]
                    self.ws.write_message(json.dumps(message))

                    state.merge('', state.pending_state)
                    state.pending_state = {}
                    self.current_mining = None

ps = []
cs = []
if __name__ == "__main__":
    conn, child_conn = multiprocessing.Pipe()
    process = multiprocessing.Process(target=pow, args=(child_conn,))
    ps.append(process)
    cs.append(conn)
    process.start()
    client = MiningClient("ws://127.0.0.1:9001/miner", 5)

    tornado.autoreload.start()
    tornado.ioloop.IOLoop.instance().start()
