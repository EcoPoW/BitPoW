from __future__ import print_function

import sys
import os
import math
import json
import time
import hashlib
import random
# import copy
# import base64
# import threading
# import secrets

if __name__ == '__main__':
    import multiprocessing
    import select
    import pprint

    import websocket

else:
    import tornado.web
    import tornado.websocket
    import tornado.ioloop
    import tornado.httpclient
    import tornado.gen
    import tornado.escape

    import setting
    import tree
    import chain
    import database

import eth_keys


# def longest_chain(from_hash = '0'*64):
#     conn = database.get_conn2()
#     c = conn.cursor()
#     c.execute("SELECT * FROM chain WHERE prev_hash = ?", (from_hash,))
#     roots = c.fetchall()

#     chains = []
#     prev_hashs = []
#     for root in roots:
#         # chains.append([root.hash])
#         chains.append([root])
#         # print(root)
#         block_hash = root[1]
#         prev_hashs.append(block_hash)

#     t0 = time.time()
#     n = 0
#     while True:
#         if prev_hashs:
#             prev_hash = prev_hashs.pop(0)
#         else:
#             break

#         c.execute("SELECT * FROM chain WHERE prev_hash = ?", (prev_hash,))
#         leaves = c.fetchall()
#         n += 1
#         if len(leaves) > 0:
#             block_height = leaves[0][3]
#             if block_height % 1000 == 0:
#                 print('longest height', block_height)
#             for leaf in leaves:
#                 for the_chain in chains:
#                     prev_block = the_chain[-1]
#                     prev_block_hash = prev_block[1]
#                     # print(prev_block_hash)
#                     if prev_block_hash == prev_hash:
#                         forking_chain = copy.copy(the_chain)
#                         # chain.append(leaf.hash)
#                         the_chain.append(leaf)
#                         chains.append(forking_chain)
#                         break
#                 leaf_hash = leaf[1]
#                 if leaf_hash not in prev_hashs and leaf_hash:
#                     prev_hashs.append(leaf_hash)
#     t1 = time.time()
#     # print(tree.current_port, "query time", t1-t0, n)

#     longest = []
#     for i in chains:
#         # print(i)
#         if not longest:
#             longest = i
#         if len(longest) < len(i):
#             longest = i
#     return longest


messages_out = []
def looping():
    global messages_out
    # print(messages_out)

    while messages_out:
        message = messages_out.pop(0)
        tree.forward(message)

    tornado.ioloop.IOLoop.instance().call_later(1, looping)


def miner_looping():
    global messages_out
    print("messages_out", len(messages_out))

    while messages_out:
        message = messages_out.pop(0)
        if tree.MinerConnector.node_miner:
            tree.MinerConnector.node_miner.write_message(tornado.escape.json_encode(message))

    tornado.ioloop.IOLoop.instance().call_later(1, miner_looping)


def get_new_difficulty(recent_longest):
    new_difficulty = 2**248
    if len(chain.recent_longest):
        timecost = chain.recent_longest[0][chain.TIMESTAMP] - chain.recent_longest[-1][chain.TIMESTAMP]
        if timecost < 1:
            timecost = 1
        adjust = timecost / (setting.BLOCK_INTERVAL_SECONDS * setting.BLOCK_DIFFICULTY_CYCLE)
        if adjust > 4:
            adjust = 4
        if adjust < 1/4:
            adjust = 1/4
        difficulty = chain.recent_longest[0][chain.DIFFICULTY]
        new_difficulty = 2**difficulty * adjust
    return new_difficulty, timecost


nonce = 0
def mining():
    global nonce
    global messages_out

    # TODO: validate with state transfer function
    highest_block_height, highest_block_hash, _highest_block = chain.get_highest_block()
    chain.recent_longest = chain.get_recent_longest(highest_block_hash)
    block_difficulty, timecost = get_new_difficulty(chain.recent_longest)
    if setting.EASY_MINING:
        block_difficulty = 2**248

    now = int(time.time())
    last_synctime = now - now % setting.NETWORK_SPREADING_SECONDS - setting.NETWORK_SPREADING_SECONDS
    nodes_to_update = {}
    for nodeid in tree.nodes_pool:
        if tree.nodes_pool[nodeid][1] < last_synctime:
            if nodeid not in chain.nodes_in_chain or chain.nodes_in_chain[nodeid][1] < tree.nodes_pool[nodeid][1]:
                # print("nodes_to_update", nodeid, nodes_in_chain[nodeid][1], tree.nodes_pool[nodeid][1], last_synctime)
                nodes_to_update[nodeid] = tree.nodes_pool[nodeid]

    # print(frozen_block_hash, longest)
    nodeno = str(tree.nodeid2no(tree.current_nodeid))
    pk = tree.node_sk.public_key
    if chain.recent_longest:
        prev_hash = chain.recent_longest[0][chain.HASH]
        height = chain.recent_longest[0][chain.HEIGHT]
        identity = chain.recent_longest[0][chain.IDENTITY]

    else:
        prev_hash, height, identity = '0'*64, 0, ":"
    new_difficulty = int(math.log(block_difficulty, 2))

    data = {}
    data["nodes"] = nodes_to_update
    data["proofs"] = list([list(p) for p in chain.last_hash_proofs])
    data["subchains"] = chain.subchains_block_to_mine
    data_json = tornado.escape.json_encode(data)

    # new_identity = "%s@%s:%s" % (tree.current_nodeid, tree.current_host, tree.current_port)
    # new_identity = "%s:%s" % (nodeno, pk)
    new_identity = pk.to_checksum_address()
    new_timestamp = time.time()
    if nonce % 1000 == 0:
        print(tree.current_port, 'mining', nonce, int(math.log(block_difficulty, 2)), height, len(chain.subchains_block_to_mine))
    for i in range(100):
        block_hash = hashlib.sha256((prev_hash + str(height+1) + str(nonce) + str(new_difficulty) + new_identity + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
        if int(block_hash, 16) < block_difficulty:
            if chain.recent_longest:
                print(tree.current_port, 'height', height, 'nodeid', tree.current_nodeid, 'nonce_init', tree.nodeid2no(tree.current_nodeid), 'timecost', timecost)

            # txid = uuid.uuid4().hex
            message = ['NEW_CHAIN_BLOCK', block_hash, prev_hash, height+1, nonce, new_difficulty, new_identity, data, new_timestamp, nodeno]
            messages_out.append(message)
            print(tree.current_port, 'mining block', height+1, block_hash, nonce)
            nonce = 0

            chain.new_chain_block(message)
            break

        if int(block_hash, 16) < block_difficulty*2:
            # if longest:
            #     print(tree.current_port, 'height', height, 'nodeid', tree.current_nodeid, 'nonce_init', tree.nodeid2no(tree.current_nodeid), 'timecost', longest[-1][7] - longest[0][7])#.timestamp

            # txid = uuid.uuid4().hex
            message = ['NEW_CHAIN_PROOF', block_hash, prev_hash, height+1, nonce, new_difficulty, new_identity, data, new_timestamp]
            messages_out.append(message)

        nonce += 1

def validate():
    global nonce

    highest_block_height, highest_block_hash, _ = chain.get_highest_block()

    db = database.get_conn()
    print('validate nodes_to_fetch', chain.nodes_to_fetch)
    fetched_nodes = set()
    for nodeid in chain.nodes_to_fetch:
        fetched_nodes.add(nodeid)
        new_chain_hash, new_chain_height = chain.fetch_chain(nodeid)
        print('validate', highest_block_hash, highest_block_height)
        print('validate', new_chain_hash, new_chain_height)
        if new_chain_height > highest_block_height:
            highest_block_hash = new_chain_hash
            highest_block_height = new_chain_height
            db.put(b"chain", highest_block_hash)

    chain.recent_longest = chain.get_recent_longest(highest_block_hash)

    chain.nodes_to_fetch = chain.nodes_to_fetch - fetched_nodes
    if not chain.nodes_to_fetch:
        if setting.MINING:
            chain.worker_thread_mining = True
            nonce = 0


def worker_thread():
    while True:
        time.sleep(2)
        if chain.worker_thread_pause:
            continue

        if chain.worker_thread_mining:
            mining()
            continue

        if tree.current_nodeid is None:
            continue

        print('chain validation')
        validate()
        print('validation done')

    # mining_task = tornado.ioloop.PeriodicCallback(mining, 1000) # , jitter=0.5
    # mining_task.start()
    # print(tree.current_port, "miner")


class Dispatcher:
    def __init__(self, app):
        self.app = app
        self.ping_timeout = 10

    def read(self, sock, read_callback, check_callback):
        global parent_conns
        while self.app.keep_running:
            r, w, e = select.select(
                    (self.app.sock.sock, ), (), (), 0.1)
            if r:
                if not read_callback():
                    break
            check_callback()

            for i in parent_conns:
                if i.poll():
                    print(i.recv())


def mine(conn):
    '''EPoW mining'''
    # msg = conn.recv()
    # conn.close()
    nonce = 0
    step = 0
    hex_to_encode = ''
    while True:
        if nonce % 1000000 == 0 and conn.poll():
            msg_json = conn.recv()
            conn.send(msg_json)

            msg = json.loads(msg_json)
            if msg[0] == 'ENCODE':
                hex_to_encode = msg[1]
                nonce = msg[2]
                step = msg[3]

        if hex_to_encode:
            output = hashlib.sha256(('%s' % nonce).encode()).hexdigest()
            if output.endswith(hex_to_encode):
                conn.send(json.dumps(['RESULT', nonce]))
                hex_to_encode = ''

            nonce += step
            if nonce % 1000000 == 0:
                # print(nonce)
                conn.send(nonce)
        else:
            time.sleep(0.1)

parent_conns = []
hex_encoding = ''
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
        process_number = int(sys.argv[2])
        parent_conns = []

        for i in range(process_number):
            parent_conn, child_conn = multiprocessing.Pipe()
            parent_conns.append(parent_conn)
            p = multiprocessing.Process(target=mine, args=(child_conn,))
            p.start()


        host = miner_obj['host']
        port = miner_obj['port']
        ws = websocket.WebSocketApp("ws://%s:%s/miner" % (host, port),
                              on_open=on_open,
                              on_message=on_message,
                              on_error=on_error,
                              on_close=on_close)
        dispatcher = Dispatcher(ws)
        ws.run_forever(dispatcher=dispatcher)

        # print(parent_conn.recv())
        # p.join()

def on_message(ws, message):
    global hex_encoding
    global parent_conns
    print(message)
    seq = json.loads(message)
    if seq[0] == 'HIGHEST_BLOCK':
        highest_block_height = seq[1]
        highest_block_hash = seq[2]
        new_difficulty = seq[3]
        print(math.log(int(new_difficulty), 2))
        # highest_block = seq[4]

    if not hex_encoding:
        hex_encoding = 'fff'
        for idx, conn in enumerate(parent_conns):
            conn.send(json.dumps(['ENCODE', hex_encoding, idx, len(parent_conns)]))


def on_error(ws, error):
    print(error)

def on_close(ws, close_status_code, close_msg):
    print("close")

def on_open(ws):
    ws.send(json.dumps(['GET_HIGHEST_BLOCK']))


if __name__ == '__main__':
    main()
    # print("run python node.py pls")
    # tree.current_port = "8001"

    # tornado.ioloop.IOLoop.instance().call_later(1, miner_looping)

    # args = parser.parse_args()
    # if not args.name:
    #     print('--name reqired')
    #     sys.exit()
    # tree.current_name = args.name
    # tree.current_host = args.host
    # tree.current_port = args.port
    # sk_filename = "miners/%s.key" % tree.current_name
    # if os.path.exists(sk_filename):
    #     f = open(sk_filename, 'rb')
    #     raw_key = f.read(32)
    #     f.close()
    #     tree.node_sk = eth_keys.keys.PrivateKey(raw_key)
    # else:
    #     raw_key = secrets.token_bytes(32)
    #     f = open(sk_filename, "wb")
    #     f.write(raw_key)
    #     f.close()
    #     tree.node_sk = eth_keys.keys.PrivateKey(raw_key)

    # database.main()

    # setting.MINING = True
    # tree.MinerConnector(tree.current_host, tree.current_port)
    # worker_threading = threading.Thread(target=worker_thread)
    # worker_threading.start()

    # tornado.ioloop.IOLoop.instance().start()
    # worker_threading.join()
