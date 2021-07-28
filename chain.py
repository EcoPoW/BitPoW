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
import urllib.request

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

import ecdsa

frozen_block_hash = '0'*64
frozen_chain = ['0'*64]
frozen_nodes_in_chain = {}
frozen_longest = []
highest_block_hash = None
recent_longest = []
nodes_in_chain = {}
worker_thread_mining = False

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

    while messages_out:
        message = messages_out.pop(0)
        if tree.MinerConnector.node_miner:
            tree.MinerConnector.node_miner.write_message(tornado.escape.json_encode(message))

    tornado.ioloop.IOLoop.instance().call_later(1, miner_looping)

nodes_to_fetch = []
highest_block_height = 0
last_highest_block_height = 0
hash_proofs = set()
last_hash_proofs = set()
subchains_block = {}
last_subchains_block = {}

@tornado.gen.coroutine
def new_chain_block(seq):
    # global frozen_block_hash
    global nodes_to_fetch
    # global recent_longest
    global worker_thread_mining
    global highest_block_height
    global last_highest_block_height
    global hash_proofs
    global last_hash_proofs
    global subchains_block
    global last_subchains_block
    msg_header, block_hash, prev_hash, height, nonce, difficulty, identity, data, timestamp, nodeno, msg_id = seq
    # validate
    # check difficulty

    conn = database.get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO chain (hash, prev_hash, height, nonce, difficulty, identity, timestamp, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (block_hash, prev_hash, height, nonce, difficulty, identity, timestamp, tornado.escape.json_encode(data)))
    except Exception as e:
        print("new_chain_block Error: %s" % e)
    conn.commit()

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
        nodes_to_fetch.append(int(nodeno))
        worker_thread_mining = False
    elif highest_block_height + 1 == height:
        highest_block_height = height

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
    # global recent_longest
    global highest_block_height
    global last_highest_block_height
    global hash_proofs
    global last_hash_proofs

    msg_header, block_hash, prev_hash, height, nonce, difficulty, identity, data, timestamp, msg_id = seq
    # validate
    # check difficulty
    print('new_chain_proof', highest_block_height, height)

    conn = database.get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO proof (hash, prev_hash, height, nonce, difficulty, identity, timestamp, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (block_hash, prev_hash, height, nonce, difficulty, identity, timestamp, tornado.escape.json_encode(data)))
    except Exception as e:
        print("new_chain_proof Error: %s" % e)
    conn.commit()

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


class GetHighestBlockHandler(tornado.web.RequestHandler):
    def get(self):
        global highest_block_hash
        self.finish({"hash": highest_block_hash})

class GetBlockHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        conn = database.get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM chain WHERE hash = ?", (block_hash,))
        block = c.fetchone()
        self.finish({"block": block[1:]})

class GetProofHandler(tornado.web.RequestHandler):
    def get(self):
        proof_hash = self.get_argument("hash")
        conn = database.get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM proof WHERE hash = ?", (proof_hash,))
        proof = c.fetchone()
        self.finish({"proof": proof[1:]})

class GetHighestSubchainBlockHandler(tornado.web.RequestHandler):
    def get(self):
        # global highest_block_hash
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
    print(tree.current_nodeid, 'fetch chain', nodeid)
    host, port = tree.current_host, tree.current_port
    prev_nodeid = None
    while True:
        try:
            response = urllib.request.urlopen("http://%s:%s/get_node?nodeid=%s" % (host, port, nodeid))
        except:
            break
        result = tornado.escape.json_decode(response.read())
        host, port = result['address']
        if result['nodeid'] == result['current_nodeid']:
            break
        if prev_nodeid == result['current_nodeid']:
            break
        prev_nodeid = result['current_nodeid']
        print('result >>>>>', nodeid, result)

    try:
        response = urllib.request.urlopen("http://%s:%s/get_highest_block" % (host, port))
    except:
        return
    result = tornado.escape.json_decode(response.read())
    block_hash = result['hash']
    if not block_hash:
        return
    # validate

    print("get highest block", block_hash)
    while block_hash != '0'*64:
        conn = database.get_conn2()
        c = conn.cursor()
        c.execute("SELECT * FROM chain WHERE hash = ?", (block_hash,))
        block = c.fetchone()
        if block:
            if block[3] % 1000 == 0: #.height
                print('block height', block[3])#.height
            block_hash = block[2]#.prev_hash
            continue
        try:
            response = urllib.request.urlopen("http://%s:%s/get_block?hash=%s" % (host, port, block_hash))
        except:
            continue
        result = tornado.escape.json_decode(response.read())
        block = result["block"]
        # if block['height'] % 1000 == 0:
        print("fetch block", block[0])
        block_hash = block[1]
        conn = database.get_conn2()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO chain (hash, prev_hash, height, nonce, difficulty, identity, timestamp, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7]))
        except Exception as e:
            print("fetch_chain Error: %s" % e)
        conn.commit()


if __name__ == '__main__':
    pass
