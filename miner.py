from __future__ import print_function

import sys
import os
import math
import argparse
import time
import uuid
import hashlib
import copy
import base64
import threading
# import urllib.request
import secrets

import tornado.web
import tornado.websocket
import tornado.ioloop
import tornado.httpclient
import tornado.gen
import tornado.escape

import setting
import tree
# import node
import chain
import database

# import ecdsa
import eth_keys


def longest_chain(from_hash = '0'*64):
    conn = database.get_conn2()
    c = conn.cursor()
    c.execute("SELECT * FROM chain WHERE prev_hash = ?", (from_hash,))
    roots = c.fetchall()

    chains = []
    prev_hashs = []
    for root in roots:
        # chains.append([root.hash])
        chains.append([root])
        # print(root)
        block_hash = root[1]
        prev_hashs.append(block_hash)

    t0 = time.time()
    n = 0
    while True:
        if prev_hashs:
            prev_hash = prev_hashs.pop(0)
        else:
            break

        c.execute("SELECT * FROM chain WHERE prev_hash = ?", (prev_hash,))
        leaves = c.fetchall()
        n += 1
        if len(leaves) > 0:
            block_height = leaves[0][3]
            if block_height % 1000 == 0:
                print('longest height', block_height)
            for leaf in leaves:
                for the_chain in chains:
                    prev_block = the_chain[-1]
                    prev_block_hash = prev_block[1]
                    # print(prev_block_hash)
                    if prev_block_hash == prev_hash:
                        forking_chain = copy.copy(the_chain)
                        # chain.append(leaf.hash)
                        the_chain.append(leaf)
                        chains.append(forking_chain)
                        break
                leaf_hash = leaf[1]
                if leaf_hash not in prev_hashs and leaf_hash:
                    prev_hashs.append(leaf_hash)
    t1 = time.time()
    # print(tree.current_port, "query time", t1-t0, n)

    longest = []
    for i in chains:
        # print(i)
        if not longest:
            longest = i
        if len(longest) < len(i):
            longest = i
    return longest


messages_out = []
def looping():
    global messages_out
    # global recent_longest
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


nonce = 0
def mining():
    global nonce
    global messages_out

    # longest = longest_chain(chain.frozen_block_hash)
    db = database.get_conn()
    highest_block_hash = db.get(b'chain')
    if highest_block_hash:
        highest_block_json = db.get(chain.highest_block_hash)
        highest_block = tornado.escape.json_decode(highest_block_json)

        if chain.highest_block_height < highest_block['height']:
            chain.highest_block_height = highest_block['height']
            chain.highest_block_hash = highest_block_hash
    else:
        chain.highest_block_hash = b'0'*64
        chain.highest_block_height = 0

    # for i in chain.frozen_longest:
    #     print("frozen longest", i[3]) #.height
    #     data = tornado.escape.json_decode(i[8])#.data
    #     chain.frozen_nodes_in_chain.update(data.get("nodes", {}))
    #     if i[1] not in chain.frozen_chain:#.hash
    #         chain.frozen_chain.append(i[1])#.hash

    # chain.nodes_in_chain = copy.copy(chain.frozen_nodes_in_chain)
    # for i in chain.recent_longest:
    #     data = tornado.escape.json_decode(i[8])#.data
    #     # for j in data.get("nodes", {}):
    #     #     print("recent longest", i.height, j, data["nodes"][j])
    #     chain.nodes_in_chain.update(data.get("nodes", {}))

    # if tree.current_nodeid not in nodes_in_chain and tree.parent_node_id_msg:
    #     tree.forward(tree.parent_node_id_msg)
    #     print(tree.current_port, 'parent_node_id_msg', tree.parent_node_id_msg)

    if len(chain.recent_longest):
        height_in_cycle = chain.recent_longest[-1][3] % setting.BLOCK_DIFFICULTY_CYCLE #.height
        timecost = chain.recent_longest[-1-height_in_cycle][7] - chain.recent_longest[-height_in_cycle-setting.BLOCK_DIFFICULTY_CYCLE][7]
        if timecost < 1:
            timecost = 1
        adjust = timecost / (setting.BLOCK_INTERVAL_SECONDS * setting.BLOCK_DIFFICULTY_CYCLE)
        if adjust > 4:
            adjust = 4
        if adjust < 1/4:
            adjust = 1/4
        difficulty = chain.recent_longest[-1][5]#.difficulty
        block_difficulty = 2**difficulty * adjust#.timestamp
    else:
        block_difficulty = 2**248

    now = int(time.time())
    last_synctime = now - now % setting.NETWORK_SPREADING_SECONDS - setting.NETWORK_SPREADING_SECONDS
    nodes_to_update = {}
    for nodeid in tree.nodes_pool:
        if tree.nodes_pool[nodeid][1] < last_synctime:
            if nodeid not in chain.nodes_in_chain or chain.nodes_in_chain[nodeid][1] < tree.nodes_pool[nodeid][1]:
                # print("nodes_to_update", nodeid, nodes_in_chain[nodeid][1], tree.nodes_pool[nodeid][1], last_synctime)
                nodes_to_update[nodeid] = tree.nodes_pool[nodeid]

    # nodes_in_chain.update(tree.nodes_pool)
    # tree.nodes_pool = nodes_in_chain
    # print(tree.nodes_pool)
    # print(nodes_to_update)

    # print(frozen_block_hash, longest)
    nodeno = str(tree.nodeid2no(tree.current_nodeid))
    pk = base64.b32encode(tree.node_sk.get_verifying_key().to_string()).decode("utf8")
    if longest:
        prev_hash = longest[-1][1]#.hash
        height = longest[-1][3]#.height
        identity = longest[-1][6]#.identity
        data = tornado.escape.json_decode(longest[-1][8])#.data
        # print(tree.dashboard_port, "new difficulty", new_difficulty, "height", height)

        # print("%s:%s" % (nodeno, pk))
        # leaders = [i for i in longest if i['timestamp'] < time.time()-setting.MAX_MESSAGE_DELAY_SECONDS and i['timestamp'] > time.time()-setting.MAX_MESSAGE_DELAY_SECONDS - setting.BLOCK_INTERVAL_SECONDS*20][-setting.LEADERS_NUM:]
        # if "%s:%s" % (nodeno, pk) in [i.identity for i in leaders]:
        #     # tornado.ioloop.IOLoop.instance().call_later(1, mining)
        #     # print([i.identity for i in leaders])
        #     return

    else:
        prev_hash, height, data, identity = '0'*64, 0, {}, ":"
    new_difficulty = int(math.log(block_difficulty, 2))

    # data = {"nodes": {k:list(v) for k, v in tree.nodes_pool.items()}}
    data["nodes"] = nodes_to_update
    data["proofs"] = list([list(p) for p in chain.last_hash_proofs])
    data["subchains"] = chain.last_subchains_block
    data_json = tornado.escape.json_encode(data)

    # new_identity = "%s@%s:%s" % (tree.current_nodeid, tree.current_host, tree.current_port)
    # new_identity = "%s:%s" % (nodeno, pk)
    new_identity = pk
    new_timestamp = time.time()
    if nonce % 1000 == 0:
        print(tree.current_port, "mining", nonce, int(math.log(block_difficulty, 2)), height, len(chain.subchains_block), len(chain.last_subchains_block))
    for i in range(100):
        block_hash = hashlib.sha256((prev_hash + str(height+1) + str(nonce) + str(new_difficulty) + new_identity + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
        if int(block_hash, 16) < block_difficulty:
            if longest:
                print(tree.current_port, 'height', height, 'nodeid', tree.current_nodeid, 'nonce_init', tree.nodeid2no(tree.current_nodeid), 'timecost', longest[-1][7] - longest[0][7])#.timestamp

            message = ["NEW_CHAIN_BLOCK", block_hash, prev_hash, height+1, nonce, new_difficulty, new_identity, data, new_timestamp, nodeno, uuid.uuid4().hex]
            messages_out.append(message)
            # print(tree.current_port, "mining", nonce, block_hash)
            nonce = 0
            break

        if int(block_hash, 16) < block_difficulty*2:
            # if longest:
            #     print(tree.current_port, 'height', height, 'nodeid', tree.current_nodeid, 'nonce_init', tree.nodeid2no(tree.current_nodeid), 'timecost', longest[-1][7] - longest[0][7])#.timestamp

            message = ["NEW_CHAIN_PROOF", block_hash, prev_hash, height+1, nonce, new_difficulty, new_identity, data, new_timestamp, uuid.uuid4().hex]
            messages_out.append(message)

        nonce += 1

def validate():
    global nonce

    db = database.get_conn()
    root_chain_hash = db.get(b"chain")
    if root_chain_hash:
        block_json = db.get(b'block%s' % root_chain_hash)
        if block_json:
            block = tornado.escape.json_decode(block_json)
            root_chain_height = block['height']
    else:
        root_chain_hash = b'0'*64
        root_chain_height = 0

    c = 0
    for nodeid in chain.nodes_to_fetch:
        c += 1
        new_chain_hash, new_chain_height = chain.fetch_chain(nodeid)
        if new_chain_height > root_chain_height:
            root_chain_hash = new_chain_hash
            root_chain_height = new_chain_height

    chain.recent_longest = []
    block_hash = root_chain_hash
    for i in range(setting.BLOCK_DIFFICULTY_CYCLE):
        block_json = db.get(block_hash)
        if block_json:
            block = tornado.escape.json_decode(block_json)
            chain.recent_longest.append(block)
        else:
            break

    # longest = longest_chain(chain.frozen_block_hash)
    # print(longest)
    # if len(longest) >= setting.FROZEN_BLOCK_NO:
    #     chain.frozen_block_hash = longest[-setting.FROZEN_BLOCK_NO][2]#.prev_hash
    #     chain.frozen_longest = longest[:-setting.FROZEN_BLOCK_NO]
    #     chain.recent_longest = longest[-setting.FROZEN_BLOCK_NO:]
    # else:
    #     chain.frozen_longest = []
    #     chain.recent_longest = longest

    # if longest:
    #     chain.highest_block_hash = longest[-1][1] #.hash
    #     if chain.highest_block_height < longest[-1][3]: #.height
    #         chain.highest_block_height = longest[-1][3] #.height
    # else:
    #     chain.highest_block_hash = '0'*64

    # for i in chain.frozen_longest:
    #     if i[3] % 1000 == 0: #.height
    #         print("frozen longest reload", i[3])#.height
    #     data = tornado.escape.json_decode(i[8]) #.data
    #     chain.frozen_nodes_in_chain.update(data.get("nodes", {}))
    #     if i[1] not in chain.frozen_chain: #.hash
    #         chain.frozen_chain.append(i[1]) #.hash

    for i in range(c):
        chain.nodes_to_fetch.pop(0)
    # print("chain.nodes_to_fetch", chain.nodes_to_fetch)
    if not chain.nodes_to_fetch:
        if setting.MINING:
            chain.worker_thread_mining = True
            nonce = 0


def worker_thread():
    db = database.get_conn(tree.current_name)
    # db.put(b'test1', b'test')
    # print(db.get(b'test1'))

    while True:
        time.sleep(2)
        if chain.worker_thread_pause:
            continue

        print('worker_thread', tree.current_nodeid)
        if chain.worker_thread_mining:
            # print('chain mining')
            mining()
            continue

        if tree.current_nodeid is None:
            continue

        # if tree.current_nodeid:
        #     fetch_chain(tree.current_nodeid[:-1])
        print('chain validation')
        validate()

    # mining_task = tornado.ioloop.PeriodicCallback(mining, 1000) # , jitter=0.5
    # mining_task.start()
    # print(tree.current_port, "miner")


if __name__ == '__main__':
    # print("run python node.py pls")
    # tree.current_port = "8001"
    # longest_chain2()
    # longest_chain()

    tornado.ioloop.IOLoop.instance().call_later(1, miner_looping)

    parser = argparse.ArgumentParser(description="python3 node.py --name=<miner_name> [--host=<127.0.0.1>] [--port=<8001>]")
    parser.add_argument('--name')
    parser.add_argument('--host')
    parser.add_argument('--port')

    args = parser.parse_args()
    if not args.name:
        print('--name reqired')
        sys.exit()
    tree.current_name = args.name
    tree.current_host = args.host
    tree.current_port = args.port
    sk_filename = "miners/%s.key" % tree.current_name
    if os.path.exists(sk_filename):
        f = open(sk_filename, 'rb')
        raw_key = f.read(32)
        f.close()
        tree.node_sk = eth_keys.keys.PrivateKey(raw_key)
    else:
        raw_key = secrets.token_bytes(32)
        f = open(sk_filename, "wb")
        f.write(raw_key)
        f.close()
        tree.node_sk = eth_keys.keys.PrivateKey(raw_key)

    database.main()

    setting.MINING = True
    tree.MinerConnector(tree.current_host, tree.current_port)
    worker_threading = threading.Thread(target=worker_thread)
    worker_threading.start()

    tornado.ioloop.IOLoop.instance().start()
    # worker_threading.join()