
import sys
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

import vm
import eth_tx
import console
import contract_erc20

contract_map = {
    '0x0000000000000000000000000000000000000001': contract_erc20
}

interface_map = {}
type_map = {}
for k, v in contract_erc20.__dict__.items():
    if not k.startswith('_') and type(v) in [types.FunctionType]:
        # print(k, type(v))
        # print(v.__code__.co_kwonlyargcount, v.__code__.co_posonlyargcount)
        # print(v.__code__.co_varnames[:v.__code__.co_argcount])
        # for i in v.__code__.co_varnames[:v.__code__.co_argcount]:
        #     print(v.__annotations__[i].__name__)
        params = [v.__annotations__[i].__name__ for i in v.__code__.co_varnames[:v.__code__.co_argcount]]
        func_sig = '%s(%s)' % (k, ','.join(params))
        # print(func_sig, '0x'+eth_utils.keccak(func_sig.encode('utf8')).hex()[:8])
        interface_map['0x'+eth_utils.keccak(func_sig.encode('utf8')).hex()[:8]] = v
        type_map[k] = params
print(interface_map)
print(type_map)

vm = vm.VM()
vm.import_module(contract_erc20)


def pow(conn):
    start = 0
    try:
        d = 10
        sleep = True
        while True:
            if conn.poll():
                m = conn.recv()
                if m[0] == 'START':
                    console.log('start')
                    start = m[1]
                    commitment = m[2]
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
                    console.log(nonce)
                h = hashlib.sha256(str(nonce).encode('utf8')).hexdigest()
                if h.startswith('0'*d):
                    # print(h, nonce)
                    conn.send(['FOUND', nonce])

            conn.send(['DONE', start, start+10000000, commitment])
            sleep = True

    except:
        pass


current_mining = None
next_mining = {}


class MiningClient:
    def __init__(self, url, timeout):
        self.url = url
        self.timeout = timeout
        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.ws = None
        self.connect()
        tornado.ioloop.PeriodicCallback(self.keep_alive, 20000).start()
        tornado.ioloop.PeriodicCallback(self.poll, 500).start()
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
        global current_mining
        global next_mining

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
                    if not current_mining:
                        current_mining = next_mining
                        next_mining = {}
                        commitment = hashlib.sha256(json.dumps(current_mining).encode('utf8')).digest()
                        conn.send(['START', 0, commitment])

                elif seq[0] == 'NEW_SUBCHAIN_BLOCK':
                    data = seq[5]
                    count = data[0]
                    signature = seq[6]
                    eth_tx_hash = eth_tx.hash_of_eth_tx_list(data)
                    signature_obj = eth_account.Account._keys.Signature(bytes.fromhex(signature[2:]))
                    pubkey = signature_obj.recover_public_key_from_msg_hash(eth_tx_hash)
                    sender = pubkey.to_checksum_address()
                    console.log('sender', sender, 'count', count)
                    print('data', data)

                    txs = next_mining.setdefault(sender, [])
                    txs.append(data)
                    #print('txs', txs)
                    print('current_mining', current_mining)
                    if not current_mining:
                        current_mining = next_mining
                        next_mining = {}
                        print('current_mining', current_mining)

                        req = requests.get('http://127.0.0.1:9001/get_chain_latest')
                        print('req', req.text)
                        obj = json.loads(req.text)
                        if obj['height'] == 0:
                            blockhash = '0'*64
                        else:
                            blockhash = obj['blockhashes'][0]

                        for addr in current_mining:
                            #print('current_mining', current_mining)
                            print('current_mining[addr]', current_mining[addr])

                        req = requests.get('http://127.0.0.1:9001/get_pool_subchains')
                        print('req', req.json())
                        pool_subchains = req.json()
                        req = requests.get('http://127.0.0.1:9001/get_state_subchains?addrs=%s' % ','.join(pool_subchains.keys()))
                        print('req', req.json())
                        state_subchains = req.json()

                        for addr in pool_subchains:
                            #print('current_mining', current_mining)
                            print('get_pool_subchains addr', addr, pool_subchains[addr])
                            to_no, to_hash = pool_subchains[addr]
                            print('get_state_subchains', state_subchains[addr])
                            from_no = 0
                            if state_subchains[addr]:
                                from_no = state_subchains[addr][0]
                            req = requests.get('http://127.0.0.1:9001/get_pool_blocks?addr=%s&from_no=%s&to_no=%s&to_hash=%s' % (addr, from_no, to_no, to_hash))
                            txblocks = req.json()['blocks']
                            txblocks.reverse()
                            for txblock in txblocks:
                                pprint.pprint(txblock)
                                tx_list = txblock[4]
                                tx_to = tx_list[4]
                                tx_data = tx_list[6]
                                tx_signature_hex = txblock[5]
                                tx_signature_obj = eth_account.Account._keys.Signature(signature_bytes=hexbytes.HexBytes(tx_signature_hex))
                                vrs = tx_signature_obj.vrs

                                tx_hash = eth_tx.hash_of_eth_tx_list(tx_list)
                                #if len(tx_list) == 8:
                                #    tx = eth_account._utils.typed_transactions.DynamicFeeTransaction.from_bytes(hexbytes.HexBytes(tx_singature_bytes))
                                #    # tx = eth_account._utils.typed_transactions.TypedTransaction(transaction_type=2, transaction=tx)
                                #    tx_hash = tx.hash()
                                #    vrs = tx.vrs()
                                #    tx_to = web3.Web3.to_checksum_address(tx.as_dict()['to'])
                                #    tx_data = web3.Web3.to_hex(tx.as_dict()['data'])
                                #    tx_nonce = web3.Web3.to_int(tx.as_dict()['nonce'])
                                #else:
                                #    tx = eth_account._utils.legacy_transactions.Transaction.from_bytes(raw_tx_bytes)
                                #    tx_hash = eth_account._utils.signing.hash_of_signed_transaction(tx)
                                #    vrs = eth_account._utils.legacy_transactions.vrs_from(tx)
                                #    tx_to = web3.Web3.to_checksum_address(tx.to)
                                #    tx_data = web3.Web3.to_hex(tx.data)
                                #    tx_nonce = tx.nonce
                                # print('eth_rlp2list', tx_list, vrs)
                                # print('nonce', tx.nonce)
                                tx_from = eth_account.Account._recover_hash(tx_hash, vrs=vrs)
                                print('tx_from', tx_from)

                                # contract_erc20._sender = tx_from
                                vm.global_vars['_sender'] = tx_from

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
                    commitment = m[3]
                    end = m[2]
                    conn.send(['START', end, commitment])
                    console.log(m)

                elif m[0] == 'FOUND':
                    # submit to chain
                    console.log(m)

ps = []
cs = []
if __name__ == "__main__":
    conn, child_conn = multiprocessing.Pipe()
    process = multiprocessing.Process(target=pow, args=(child_conn,))
    ps.append(process)
    cs.append(conn)
    process.start()
    client = MiningClient("ws://127.0.0.1:9001/miner", 5)

