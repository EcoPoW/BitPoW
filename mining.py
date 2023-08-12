
import sys
import time
import hashlib
import multiprocessing
import json
# import threading
# import curses

# import eth_hash.auto
import web3
import eth_account
import requests

import tornado.ioloop
import tornado.gen
import tornado.websocket

import vm
import eth_tx
import console

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
                console.log(msg)
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
                    console.log('sender', sender)
                    console.log('count', count)
                    console.log('data', data)

                    txs = next_mining.get(sender, [])
                    console.log('txs', txs)
                    if not current_mining:
                        current_mining = next_mining
                        next_mining = {}


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

