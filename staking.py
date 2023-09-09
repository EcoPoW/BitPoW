
import sys
import uuid
import random
import hashlib
import json
import pprint
import select
import multiprocessing
import math

import websocket

# staking = {uuid.uuid4().hex: (random.randint(1, 1000), random.randint(10000000, 100000000000000)) for i in range(5, 500000)}


# total = sum([i[0] for i in staking.values()])
# print('total', total)

# blockhash = uuid.uuid4().hex
# print('blockhash', blockhash)

# pointer = (int(blockhash, 16)) % total
# print('pointer', pointer)
# for user, (token, secret) in staking.items():
#     user_pointer = (int(blockhash, 16) + secret) % total
#     rate = abs(user_pointer - pointer)/token
#     if rate < 3:
#         print(user, rate, token)


# class Dispatcher:
#     def __init__(self, app):
#         self.app = app
#         self.ping_timeout = 10

#     def read(self, sock, read_callback, check_callback):
#         global parent_conns
#         global hex_encoding
#         nonce = 0
#         task = 0
#         while self.app.keep_running:
#             r, w, e = select.select(
#                     (self.app.sock.sock, ), (), (), 0.1)
#             if r:
#                 if not read_callback():
#                     break
#             check_callback()

#             for idx, conn in enumerate(parent_conns):
#                 if conn.poll():
#                     msg_json = conn.recv()
#                     print(idx, msg_json)
#                     msg = json.loads(msg_json)
#                     if msg[0] == 'RESULT' and msg[1] == task:
#                         hex_encoding = ''
#                         task += 1
#                         nonce = msg[2] + 1

#             if not hex_encoding:
#                 hex_encoding = 'ffffff'
#                 for idx, conn in enumerate(parent_conns):
#                     # print(hex_encoding)
#                     conn.send(json.dumps(['ENCODE', task, hex_encoding, nonce+idx, len(parent_conns)]))


def main():
    global parent_conns
    # print(sys.argv)
    if len(sys.argv) < 2:
        print('help')
        print('  miner.py key')
        print('  miner.py host')
        print('  miner.py port')
        print('  miner.py mine')
        return

    miner_obj = {}
    try:
        with open('./.miner.json', 'r') as f:
            miner_obj = json.loads(f.read())
            pprint.pprint(miner_obj)

    except:
        print('error')

    if sys.argv[1] in ['key', 'host', 'port']:
        miner_obj[sys.argv[1]] = sys.argv[2]
        with open('./.miner.json', 'w') as f:
            f.write(json.dumps(miner_obj))
        return

    elif sys.argv[1] == 'mine':
        # process_number = int(sys.argv[2])
        parent_conns = []

        # for i in range(process_number):
        #     parent_conn, child_conn = multiprocessing.Pipe()
        #     parent_conns.append(parent_conn)
        #     p = multiprocessing.Process(target=mine, args=(child_conn,))
        #     p.start()


        host = miner_obj['host']
        port = miner_obj['port']
        ws = websocket.WebSocketApp("ws://%s:%s/miner" % (host, port),
                              on_open=on_open,
                              on_message=on_message,
                              on_error=on_error,
                              on_close=on_close)
        # dispatcher = Dispatcher(ws)
        # ws.run_forever(dispatcher=dispatcher)
        ws.run_forever()

        # print(parent_conn.recv())
        # p.join()

def on_message(ws, message):
    # global hex_encoding
    # global parent_conns
    print(message)
    seq = json.loads(message)
    if seq[0] == 'HIGHEST_BLOCK':
        highest_block_height = seq[1]
        highest_block_hash = seq[2]
        new_difficulty = seq[3]
        print(math.log(int(new_difficulty), 2), int(new_difficulty))
        # highest_block = seq[4]
        ws.send(json.dumps(['GET_BLOCK_STATE', highest_block_hash]))


def on_error(ws, error):
    print(error)

def on_close(ws, close_status_code, close_msg):
    print("close")

def on_open(ws):
    ws.send(json.dumps(['GET_HIGHEST_BLOCK']))


if __name__ == '__main__':
    main()
