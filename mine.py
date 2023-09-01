
import sys
import os
import math
import time
import hashlib
import uuid
import copy
# import json
# import random
# import base64
# import threading
# import secrets

# if __name__ == '__main__':
#     import multiprocessing
# import select
# import pprint

#     import websocket

# else:
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
import console

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


def get_new_difficulty(recent_longest):
    new_difficulty = 2**248
    timecost = 0
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
        block_difficulty = 2**255

    now = int(time.time())
    last_synctime = now - now % setting.NETWORK_SPREADING_SECONDS - setting.NETWORK_SPREADING_SECONDS
    nodes_to_update = {}
    for nodeid in tree.nodes_pool:
        if tree.nodes_pool[nodeid][3] < last_synctime:
            if nodeid not in chain.nodes_in_chain or chain.nodes_in_chain[nodeid][1] < tree.nodes_pool[nodeid][3]:
                # print('nodes_to_update', nodeid, nodes_in_chain[nodeid][1], tree.nodes_pool[nodeid][3], last_synctime)
                nodes_to_update[nodeid] = tree.nodes_pool[nodeid]

    # print(frozen_block_hash, longest)
    # nodeno = str(tree.nodeid2no(tree.current_nodeid))
    pk = tree.node_sk.public_key
    if chain.recent_longest:
        prev_hash = chain.recent_longest[0][chain.HASH]
        height = chain.recent_longest[0][chain.HEIGHT]
        identity = chain.recent_longest[0][chain.IDENTITY]

    else:
        prev_hash, height, identity = '0'*64, 0, ':'
    new_difficulty = int(math.log(block_difficulty, 2))

    data = {}
    data['nodes'] = nodes_to_update
    data['proofs'] = list([list(p) for p in chain.last_hash_proofs])
    data['subchains'] = chain.subchains_to_block
    data['tokens'] = chain.tokens_to_block
    data['aliases'] = chain.aliases_to_block
    data_json = tornado.escape.json_encode(data)

    # new_identity = "%s@%s:%s" % (tree.current_nodeid, tree.current_host, tree.current_port)
    # new_identity = "%s:%s" % (nodeno, pk)
    new_identity = pk.to_checksum_address()
    new_timestamp = time.time()
    # if nonce % 1000 == 0:
    #     print(tree.current_port, 'mining', nonce, int(math.log(block_difficulty, 2)), height, len(chain.subchains_to_block))
    for i in range(100):
        block_hash_obj = hashlib.sha256((prev_hash + str(height+1) + str(nonce) + str(new_difficulty) + new_identity + data_json + str(new_timestamp)).encode('utf8'))
        block_hash = block_hash_obj.hexdigest()
        block_hash_bytes = block_hash_obj.digest()
        if int(block_hash, 16) < block_difficulty:
            # if chain.recent_longest:
            #     print(tree.current_port, 'height', height, 'nodeid', tree.current_nodeid, 'nonce_init', tree.nodeid2no(tree.current_nodeid), 'timecost', timecost)

            sig = tree.node_sk.sign_msg_hash(block_hash_bytes)
            # print(sig)
            txid = uuid.uuid4().hex
            message = ['NEW_CHAIN_BLOCK', block_hash, prev_hash, height+1, nonce, new_difficulty, new_identity, data, new_timestamp, sig.to_hex(), txid]
            messages_out.append(message)
            print(tree.current_port, 'mining block', height+1, block_hash, nonce)
            nonce = 0

            chain.new_chain_block(message)
            break

        if int(block_hash, 16) < block_difficulty*2:
            # if longest:
            #     print(tree.current_port, 'height', height, 'nodeid', tree.current_nodeid, 'nonce_init', tree.nodeid2no(tree.current_nodeid), 'timecost', longest[-1][7] - longest[0][7])#.timestamp

            txid = uuid.uuid4().hex
            message = ['NEW_CHAIN_PROOF', block_hash, prev_hash, height+1, nonce, new_difficulty, new_identity, data, new_timestamp, txid]
            # messages_out.append(message)

        nonce += 1

def validate():
    global nonce

    highest_block_height, highest_block_hash, _ = chain.get_highest_block()

    db = database.get_conn()
    #print('validate nodes_to_fetch', chain.nodes_to_fetch)
    fetched_nodes = set()
    nodes_to_fetch = copy.copy(chain.nodes_to_fetch)
    for nodeid in nodes_to_fetch:
        fetched_nodes.add(nodeid)
        new_chain_hash, new_chain_height = chain.fetch_chain(nodeid)
        # print('validate', highest_block_hash, highest_block_height)
        # print('validate', new_chain_hash, new_chain_height)
        if new_chain_height > highest_block_height:
            highest_block_hash = new_chain_hash
            highest_block_height = new_chain_height
            db.put(b'chain', highest_block_hash)

    chain.recent_longest = chain.get_recent_longest(highest_block_hash)

    chain.nodes_to_fetch = chain.nodes_to_fetch - fetched_nodes


