from __future__ import print_function

# import sys
# import os
# import math
# import argparse
import time
# import uuid
# import hashlib
import copy
# import base64
# import threading
import urllib.request
# import secrets

import tornado.web
import tornado.websocket
import tornado.ioloop
import tornado.httpclient
import tornado.gen
import tornado.escape

import setting
import tree
# import node
# import leader
import database

# import ecdsa
# import eth_keys

HASH = 0
PREV_HASH = 1
HEIGHT = 2
NONCE = 3
DIFFICULTY = 4
IDENTITY = 5
DATA = 6
TIMESTAMP = 7
NODE = 8
MSGID = 9

# frozen_block_hash = '0'*64
# frozen_chain = ['0'*64]
# frozen_nodes_in_chain = {}
# frozen_longest = []
recent_longest = []
nodes_in_chain = {}
worker_thread_mining = False
worker_thread_pause = True

def longest_chain(from_hash = '0'*64):
    db = database.get_conn()
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
                for chain in chains:
                    prev_block = chain[-1]
                    prev_block_hash = prev_block[1]
                    # print(prev_block_hash)
                    if prev_block_hash == prev_hash:
                        forking_chain = copy.copy(chain)
                        # chain.append(leaf.hash)
                        chain.append(leaf)
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


nodes_to_fetch = []
# highest_block_height = 0
last_highest_block_height = 0
hash_proofs = set()
last_hash_proofs = set()
subchains_block = {}
last_subchains_block = {}

@tornado.gen.coroutine
def new_chain_block(seq):
    global nodes_to_fetch
    global worker_thread_mining
    # global highest_block_height
    global last_highest_block_height
    global hash_proofs
    global last_hash_proofs
    global subchains_block
    global last_subchains_block
    msg_header, block_hash, prev_hash, height, nonce, difficulty, identity, data, timestamp, nodeno, msg_id = seq
    # validate
    # check difficulty

    db = database.get_conn()
    highest_block_hash = db.get(b'chain')
    if highest_block_hash:
        highest_block_json = db.get(b'block%s' % highest_block_hash)
        if highest_block_json:
            highest_block = tornado.escape.json_decode(highest_block_json)
            highest_block_height = highest_block[HEIGHT]
            if highest_block_height < height:
                # try:
                db.put(b'block%s' % block_hash.encode('utf8'), tornado.escape.json_encode(seq[1:]).encode('utf8'))
                db.put(b'chain', block_hash.encode('utf8'))
                # except Exception as e:
                #     print("new_chain_block Error: %s" % e)

    # if prev_hash != '0'*64:
    #     prev_block = database.connection.get("SELECT * FROM chain"+tree.current_port+" WHERE hash = %s", prev_hash)
    #     if not prev_block:
    #         no, pk = identity.split(":")
    #         if int(no) not in nodes_to_fetch:
    #             nodes_to_fetch.append(int(no))
    #         worker_thread_mining = False

    print(highest_block_height, height, identity)
    if highest_block_height + 1 < height:
        # no, pk = identity.split(":")
        # if int(no) not in nodes_to_fetch:
        nodes_to_fetch.append(tree.nodeno2id(int(nodeno)))
    elif highest_block_height + 1 == height:
        highest_block_height = height
    worker_thread_mining = False

    print('new_chain_block', last_highest_block_height, highest_block_height)
    if last_highest_block_height != highest_block_height:
        last_subchains_block = subchains_block
        subchains_block = {}
        if last_highest_block_height + 1 == highest_block_height:
            last_hash_proofs = hash_proofs
        else:
            last_hash_proofs = set()
        hash_proofs = set()
        last_highest_block_height = highest_block_height

@tornado.gen.coroutine
def new_chain_proof(seq):
    global nodes_to_fetch
    # global highest_block_height
    global last_highest_block_height
    global hash_proofs
    global last_hash_proofs

    msg_header, block_hash, prev_hash, height, nonce, difficulty, identity, data, timestamp, msg_id = seq
    # validate
    # check difficulty
    print('new_chain_proof', highest_block_height, height)

    db = database.get_conn()
    # try:
    db.put(b'block%s' % block_hash.encode('utf8'), tornado.escape.json_encode(data).encode('utf8'))
    # except Exception as e:
    #     print("new_chain_proof Error: %s" % e)

    print(highest_block_height, height, identity)
    # if highest_block_height + 1 < height:
    #     no, pk = identity.split(":")
    #     if int(no) not in nodes_to_fetch:
    #         nodes_to_fetch.append(int(no))

    if last_highest_block_height != highest_block_height:
        if last_highest_block_height + 1 == highest_block_height:
            last_hash_proofs = hash_proofs
        else:
            last_hash_proofs = set()
        hash_proofs = set()
        # last_highest_block_height = highest_block_height

    if highest_block_height + 1 == height:
        hash_proofs.add(tuple([block_hash, height]))

    print('hash_proofs', hash_proofs)
    print('last_hash_proofs', last_hash_proofs)

@tornado.gen.coroutine
def new_subchain_block(seq):
    global subchains_block
    # global last_subchains_block
    msg_header, block_hash, prev_hash, sender, receiver, height, data, timestamp, signature = seq
    # validate
    # need to ensure current subchains_block[sender] is the ancestor of block_hash
    print('new_subchain_block', block_hash, prev_hash, sender, receiver, height, data, timestamp, signature)
    subchains_block[sender] = block_hash

    conn = database.get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO subchains (hash, prev_hash, sender, receiver, height, timestamp, data, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (block_hash, prev_hash, sender, receiver, height, timestamp, tornado.escape.json_encode(data), signature))
    except Exception as e:
        print("new_subchain_block Error: %s" % e)
    conn.commit()


class GetHighestBlockHashesHandler(tornado.web.RequestHandler):
    def get(self):
        db = database.get_conn()
        highest_block_height = 0
        highest_block_hash = db.get(b'chain')
        if highest_block_hash:
            highest_block_json = db.get(b'block%s' % highest_block_hash)
            if highest_block_json:
                highest_block = tornado.escape.json_decode(highest_block_json)
                highest_block_height = highest_block[HEIGHT]

        self.finish({'hash': highest_block_hash.decode('utf8'), 'height': highest_block_height})

class GetBlockHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        db = database.get_conn()
        block_json = db.get(b'block%s' % block_hash.encode('utf8'))
        if block_json:
            self.finish({"block": tornado.escape.json_decode(block_json)})
        else:
            self.finish({"block": None})

class GetProofHandler(tornado.web.RequestHandler):
    def get(self):
        proof_hash = self.get_argument("hash")
        conn = database.get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM proof WHERE hash = ?", (proof_hash,))
        proof = c.fetchone()
        self.finish({"proof": proof[1:]})

class GetHighestSubchainBlockHashHandler(tornado.web.RequestHandler):
    def get(self):
        # TODO: fixed key 'chain0x0000' for rocksdb
        sender = self.get_argument('sender')
        conn = database.get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM subchains WHERE sender = ? ORDER BY height DESC LIMIT 1", (sender,))
        block = c.fetchone()
        if block:
            self.finish({"hash": block[1]})
        else:
            self.finish({"hash": '0'*64})

class GetSubchainBlockHandler(tornado.web.RequestHandler):
    def get(self):
        # TODO: combine with GetBlockHandler
        block_hash = self.get_argument("hash")
        conn = database.get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM subchains WHERE hash = ?", (block_hash,))
        block = c.fetchone()
        if block:
            self.finish({"block": block[1:]})
        else:
            self.finish({"block": None})

def fetch_chain(nodeid):
    print('node', tree.current_nodeid, 'fetch chain', nodeid)
    host, port = tree.current_host, tree.current_port
    prev_nodeid = None
    while True:
        try:
            response = urllib.request.urlopen("http://%s:%s/get_node?nodeid=%s" % (host, port, nodeid))
        except:
            break
        result = tornado.escape.json_decode(response.read())
        print('fetch_chain result', nodeid, result)
        host, port = result['address']
        if result['nodeid'] == result['current_nodeid']:
            break
        if prev_nodeid == result['current_nodeid']:
            break
        prev_nodeid = result['current_nodeid']

    try:
        response = urllib.request.urlopen("http://%s:%s/get_highest_block" % (host, port))
    except:
        return b'0'*64, 0
    result = tornado.escape.json_decode(response.read())
    highest_block_hash = result['hash']
    highest_block_height = result['height']
    if not highest_block_hash:
        return b'0'*64, 0

    db = database.get_conn()
    print('fetch_chain get highest block', highest_block_hash, highest_block_height, host, port)

    # validate
    block_hash = highest_block_hash
    while block_hash != '0'*64:
        block_json = db.get(b'block%s' % block_hash.encode('utf8'))
        if block_json:
            # block = tornado.escape.json_decode(block_json)
            # if block[HEIGHT] % 1000 == 0:
            #     print('fetch_chain block height', block[HEIGHT])
            # block_hash = block[PREV_HASH]
            break

        try:
            response = urllib.request.urlopen('http://%s:%s/get_block?hash=%s' % (host, port, block_hash))
        except:
            # continue
            return b'0'*64, 0
        result = tornado.escape.json_decode(response.read())
        block = result['block']
        # if block['height'] % 1000 == 0:
        print('fetch_chain block', block[HASH])

        # try:
        db.put(b'block%s' % block_hash.encode('utf8'), tornado.escape.json_encode(block).encode('utf8'))
        # except Exception as e:
        #     print('fetch_chain Error: %s' % e)
        block_hash = block[PREV_HASH]

    return highest_block_hash.encode('utf8'), highest_block_height

if __name__ == '__main__':
    pass
