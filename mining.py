
import sys
import time
import hashlib
import multiprocessing
import json
# import threading
# import curses

# import eth_hash.auto
import web3

import tornado.ioloop
import tornado.gen
import tornado.websocket

import vm

def pow(conn):
    start = 0
    try:
        d = 10
        sleep = True
        while True:
            if conn.poll():
                m = conn.recv()
                if m[0] == 'START':
                    print('start')
                    start = m[1]
                    commitment = m[2]
                    sleep = False
                elif m[0] == 'STOP':
                    sleep = True

            if sleep:
                time.sleep(1)
                print('sleep')
                continue

            # t0 = time.time()
            nonce = start
            for nonce in range(start, start+10000000):
                if nonce % 100000 == 0:
                    print(nonce)
                h = hashlib.sha256(str(nonce).encode('utf8')).hexdigest()
                if h.startswith('0'*d):
                    # print(h, nonce)
                    conn.send(['FOUND', nonce])

            conn.send(['DONE', start, start+10000000, commitment])
            sleep = True
    except:
        pass


current_mining = None
next_mining = []


class MiningClient:
    def __init__(self, url, timeout):
        self.url = url
        self.timeout = timeout
        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.ws = None
        self.connect()
        tornado.ioloop.PeriodicCallback(self.keep_alive, 20000).start()
        tornado.ioloop.PeriodicCallback(self.pool, 500).start()
        self.ioloop.start()

    @tornado.gen.coroutine
    def connect(self):
        print("trying to connect")
        try:
            self.ws = yield tornado.websocket.websocket_connect(self.url)
        except Exception:
            print("connection error")
        else:
            print("connected")
            self.run()

    @tornado.gen.coroutine
    def run(self):
        global current_mining
        global next_mining
        while True:
            msg = yield self.ws.read_message()
            if msg is None:
                print("connection closed")
                self.ws = None
                break
            else:
                print('run', msg)
                seq = json.loads(msg)
                if seq[0] == '_NEW_CHAIN_BLOCK':
                    # next_mining.append(message['name'])
                    if not current_mining:
                        current_mining = next_mining
                        next_mining = []
                        commitment = hashlib.sha256(json.dumps(current_mining).encode('utf8')).digest()
                        conn.send(['START', 0, commitment])

                elif seq[0] == 'NEW_SUBCHAIN_BLOCK':
                    pass

    def keep_alive(self):
        if self.ws is None:
            self.connect()
        else:
            self.ws.write_message('["KEEP_ALIVE"]')

    def pool(self):
        for conn in cs:
            if conn.poll(0.1):
                m = conn.recv()
                if m[0] == 'DONE':
                    # continue
                    commitment = m[3]
                    end = m[2]
                    conn.send(['START', end, commitment])
                    print('DONE', m)

                elif m[0] == 'FOUND':
                    # submit to chain
                    print('FOUND', m)

ps = []
cs = []
if __name__ == "__main__":
    conn, child_conn = multiprocessing.Pipe()
    process = multiprocessing.Process(target=pow, args=(child_conn,))
    ps.append(process)
    cs.append(conn)
    process.start()
    client = MiningClient("ws://127.0.0.1:9001/miner", 5)
