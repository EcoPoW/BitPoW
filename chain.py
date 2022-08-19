from __future__ import print_function

# import sys
# import os
# import math
# import argparse
# import uuid
# import base64
# import threading
# import secrets
import time
import hashlib
import copy
import urllib.request

import tornado.web
import tornado.websocket
import tornado.ioloop
import tornado.httpclient
import tornado.gen
import tornado.escape

import setting
import tree
import database
import stf
import rpc
# import node
# import leader

import eth_keys
import eth_utils
# import ecdsa

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

SENDER = 2
RECEIVER = 3
MSG_HEIGHT = 4
MSG_DATA = 5
REF_HASH = 6
REF_HEIGHT = 7

recent_longest = []
nodes_in_chain = {}
worker_thread_mining = False
worker_thread_pause = True

# def longest_chain(from_hash = '0'*64):
#     db = database.get_conn()
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
#                 for chain in chains:
#                     prev_block = chain[-1]
#                     prev_block_hash = prev_block[1]
#                     # print(prev_block_hash)
#                     if prev_block_hash == prev_hash:
#                         forking_chain = copy.copy(chain)
#                         # chain.append(leaf.hash)
#                         chain.append(leaf)
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


nodes_to_fetch = set()
last_highest_block_height = 0
hash_proofs = set()
last_hash_proofs = set()

subchains_to_block = {}
tokens_to_block = {}
aliases_to_block = {}
balances_to_collect = {}

# @tornado.gen.coroutine
def new_chain_block(seq):
    global nodes_to_fetch
    global worker_thread_mining
    global recent_longest
    global last_highest_block_height
    global hash_proofs
    global last_hash_proofs
    global subchains_to_block
    global tokens_to_block
    global aliases_to_block
    global balances_to_collect
    _msg_header, block_hash, prev_hash, height, nonce, difficulty, identity, data, timestamp, signature, txid = seq

    # validate hash
    data_json = tornado.escape.json_encode(data)
    assert block_hash == hashlib.sha256((prev_hash + str(height) + str(nonce) + str(difficulty) + identity + data_json + str(timestamp)).encode('utf8')).hexdigest()
    # check difficulty

    db = database.get_conn()
    highest_block_hash = db.get(b'chain')
    if highest_block_hash:
        highest_block_json = db.get(b'block%s' % highest_block_hash)
        if highest_block_json:
            highest_block = tornado.escape.json_decode(highest_block_json)
            highest_block_height = highest_block[HEIGHT]
    else:
        highest_block_height = 0
        highest_block_hash = b'0'*64

    # print('new_chain_block', block_hash)
    # validate signature
    sig = eth_keys.keys.Signature(eth_utils.hexadecimal.decode_hex(signature))
    pk = sig.recover_public_key_from_msg_hash(eth_utils.hexadecimal.decode_hex(block_hash))
    # print('sig', pk)
    # print('id', pk.to_checksum_address(), identity)
    assert pk.to_checksum_address() == identity

    # validate nonce
    if highest_block_height >= height - 1: # and highest_block_hash.decode() == prev_hash
        prev_blockstate = {}
        blockstate = {}

        if highest_block_height: # load prev full state
            prev_blockstate_json = db.get(b'blockstate_%s' % prev_hash.encode('utf8'))
            if prev_blockstate_json:
                prev_blockstate = tornado.escape.json_decode(prev_blockstate_json)
                # check/fetch subchains msg in detail, compare with prev blockstate, eg, balance
                # blockstate = prev_blockstate
                # blockstate.setdefault('nodes', {}).update(data.get('nodes', {}))
                # blockstate.setdefault('subchains', {}).update(data.get('subchains', {}))
                blockstate = stf.chain_stf(prev_blockstate, data)

        # verify subchains
        subchains = data.get('subchains', {})
        print('subchains', subchains)
        for address, confirmed_msg_hash in subchains.items():
            print('full state subchains', blockstate.get('subchains', {}).get(address))
            # print('prev full state subchains', prev_blockstate.get('subchains', {}).get(address))
            msg_hash = blockstate.get('subchains', {}).get(address)
            prev_msg_hash = msg_hash
            # print(prev_blockstate)
            last_confirmed_msg_hash = prev_blockstate.get('subchains', {}).get(address, '0'*64)
            # print('last_confirmed_msg_hash', last_confirmed_msg_hash)
            # verify messages on subchain
            while True:
                msg_json = db.get(b'msg%s' % prev_msg_hash.encode('utf8'))
                if not msg_json:
                    continue
                msg = tornado.escape.json_decode(msg_json)
                # print('new_chain_block msg', address, msg)
                # if 'eth_raw_tx' in msg[MSG_DATA]:
                #     raw_tx = msg[MSG_DATA]['eth_raw_tx']
                #     tx, _tx_from, tx_to, _tx_hash = rpc.tx_info(raw_tx)
                #     balances_to_collect.setdefault(tx_to, set())
                #     balances_to_collect[tx_to].add(prev_msg_hash)

                address = msg[SENDER]
                sender_hash = msg[REF_HASH]
                pool_value = db.get(('pool%s_%s' % (address, sender_hash)).encode('utf8'))
                print('pool', address, sender_hash)
                if pool_value:
                    print('delete pool', address, sender_hash)
                    db.delete(('pool%s_%s' % (address, sender_hash)).encode('utf8'))

                prev_msg_hash = msg[PREV_HASH]
                # print('new_chain_block msg parent hash', prev_msg_hash)
                if prev_msg_hash == '0'*64:
                    break
                if prev_msg_hash == last_confirmed_msg_hash:
                    # print('verify done', address, prev_msg_hash, last_confirmed_msg_hash)
                    break

        data_clone = copy.copy(data)
        # data_clone['balances_to_collect'] = balances_to_collect
        blockstate = stf.chain_stf(prev_blockstate, data_clone)

        db.put(b'blockstate_%s' % block_hash.encode('utf8'), tornado.escape.json_encode(blockstate).encode('utf8'))
        # try:
        db.put(b'block%s' % block_hash.encode('utf8'), tornado.escape.json_encode(seq[1:]).encode('utf8'))
        if highest_block_height == height - 1:
            db.put(b'chain', block_hash.encode('utf8'))
            recent_longest.insert(0, seq[1:])
        # except Exception as e:
        #     print("new_chain_block Error: %s" % e)

        if len(recent_longest) > setting.BLOCK_DIFFICULTY_CYCLE:
            recent_longest.pop()
        highest_block_height = height

        # prepare the data for mining next block
        subchains_to_block = {}
        tokens_to_block = {}
        aliases_to_block = {}

        # print('prev_blockstate', prev_blockstate)
        prev_subchains_highest = {}
        for contract_address, contract_hash in prev_blockstate.get('subchains', {}).items():
            # print(contract_address, contract_hash)
            msg_json = db.get(b'msg%s' % contract_hash.encode('utf8'))
            if not msg_json:
                continue
            msg = tornado.escape.json_decode(msg_json)
            # print(msg)
            # print(msg[SENDER])
            # print(msg[REF_HEIGHT], msg[REF_HASH])
            msg_height, msg_hash = prev_subchains_highest.get(msg[SENDER], (0, '0'*64))
            if msg[REF_HEIGHT] > msg_height:
                # print(msg_height, msg_hash)
                prev_subchains_highest[msg[SENDER]] = (msg[REF_HEIGHT], msg[REF_HASH])
        print('prev_subchains_highest', prev_subchains_highest)

        pool_address_pending = {}
        it = db.iteritems()
        it.seek(b'pool')
        for pool_key, pool_value in it:
            if len(subchains_to_block) >= 9400:
                break
            # if len(subchains_to_block) >= 400:
            #     break
            if not pool_key.startswith(b'pool'):
                break
            key_items = pool_key[4:].split(b'_')
            if len(key_items) != 2:
                break
            value_items = pool_value.split(b'_')
            if len(value_items) != 2:
                break
            msg_address, msg_hash = key_items
            msg_height = int(value_items[0])
            prev_msg_hash = value_items[1]
            # print('pool_key', pool_key)
            # print('pool_value', msg_address, msg_height, msg_hash, prev_msg_hash)
            pool_address_pending.setdefault(msg_address, set())
            pool_address_pending[msg_address].add((msg_height, msg_hash, prev_msg_hash))

        contracts_to_interact = []
        for msg_address, msgs_set in pool_address_pending.items():
            _last_confirmed_msg_height, last_confirmed_msg_hash = prev_subchains_highest.get(msg_address.decode('utf8'), (0, '0'*64))
            last_confirmed_msg_hash = last_confirmed_msg_hash.encode('utf8')
            msgs = list(msgs_set)
            msgs.sort()
            # print('msgs', msgs)
            for msg_height, msg_hash, prev_msg_hash in msgs:
                print(msg_height, prev_msg_hash, last_confirmed_msg_hash)
                if prev_msg_hash == last_confirmed_msg_hash:
                    print('msg', msg_hash)
                    msg_json = db.get(b'msg%s' % msg_hash)
                    print(msg_json)
                    if not msg_json:
                        continue
                    msg = tornado.escape.json_decode(msg_json)
                    print('new_chain_block msg', msg)

                    if msg[MSG_DATA].get('type') == 'new_asset':
                        # token = msg[MSG_DATA]['name']
                        # tokens_to_block[token] = address
                        address = msg[MSG_DATA]['creator']

                    elif msg[MSG_DATA].get('type') == 'new_alias':
                        alias = msg[MSG_DATA]['name']
                        address = msg[MSG_DATA]['address']
                        aliases_to_block[alias] = address

                    if msg[RECEIVER] == '1x':
                        contracts_to_interact.append(msg[HASH])

                    if msg[RECEIVER].startswith('1x') and len(msg[RECEIVER]) == 42:
                        contracts_to_interact.append(msg[HASH])

                    last_confirmed_msg_hash = msg_hash

        for i in contracts_to_interact:
            print('contracts_to_interact', i)
            msg_json = db.get(b'msg%s' % i.encode('utf8'))
            msg = tornado.escape.json_decode(msg_json)
            # print(msg)

            if msg[RECEIVER] == '1x':
                # new_contract_block
                # new_contract_address = '0x%s' % msg[HASH]
                msg_hash = msg[HASH]
                msg_sender = msg[SENDER]
                msg_height = msg[MSG_HEIGHT]
                msg_data = msg[MSG_DATA]
                # print('mining new_contract', msg_hash)
                # print('mining new_contract_address', new_contract_address)

                # new_timestamp = time.time()
                new_contract_hash = hashlib.sha256(('0'*64 + msg_sender + '' + str(1) + tornado.escape.json_encode(msg_data) + msg_hash + str(msg_height)).encode('utf8')).hexdigest()
                # contract_signature = tree.node_sk.sign_msg(str(new_contract_hash).encode("utf8"))
                # print('mining signature', contract_signature.to_hex())
                new_contract_block = [new_contract_hash, '0'*64, msg_sender, '', 1, msg_data, msg_hash, msg_height]
                new_contract_address = '1x%s' % new_contract_hash[:40]

                msgstate = stf.subchain_stf({}, msg_data)
                # print('msgstate', msgstate)
                msgstate_json = tornado.escape.json_encode(msgstate)
                # print('msgstate_json', msgstate_json)
                # print('new_contract_hash', new_contract_hash)
                db.put(b'msgstate_%s' % new_contract_hash.encode('utf8'), msgstate_json.encode('utf8'))

                db.put(b'msg%s' % new_contract_hash.encode('utf8'), tornado.escape.json_encode(new_contract_block).encode('utf8'))
                db.put(b'chain%s' % new_contract_address.encode('utf8'), new_contract_hash.encode('utf8'))

                subchains_to_block[new_contract_address] = new_contract_hash

            elif len(msg[RECEIVER]) == 42 and msg[RECEIVER].startswith('1x'):
                print('new_chain_block msg to contract', msg)
                msg_hash = msg[HASH]
                msg_sender = msg[SENDER]
                msg_receiver = msg[RECEIVER]
                msg_height = msg[MSG_HEIGHT]
                msg_data = msg[MSG_DATA]
                # user_msg_hash = msg[REF_HASH]
                # user_msg_height = msg[REF_HEIGHT]

                contract_parent_hash = db.get(b'chain%s' % msg_receiver.encode('utf8'))
                # print(b'chain%s' % msg_receiver.encode('utf8'))
                # print(contract_parent_hash)
                contract_block_json = db.get(b'msg%s' % contract_parent_hash)
                contract_block = tornado.escape.json_decode(contract_block_json)
                contract_height = contract_block[MSG_HEIGHT] + 1
                # contract_parent_hash = contract_block[PREV_HASH]
                # contract_data = contract_block[MSG_DATA]

                # new_timestamp = time.time()
                new_contract_hash = hashlib.sha256((contract_parent_hash.decode('utf8') + msg_sender + '' + str(contract_height) + tornado.escape.json_encode(msg_data) + msg_hash + str(msg_height)).encode('utf8')).hexdigest()
                # contract_signature = tree.node_sk.sign_msg(str(new_contract_hash).encode("utf8"))
                # print('mining signature', contract_signature.to_hex())
                new_contract_block = [new_contract_hash, contract_parent_hash.decode('utf8'), msg_sender, '', contract_height, msg_data, msg_hash, msg_height]

                db.put(b'msg%s' % new_contract_hash.encode('utf8'), tornado.escape.json_encode(new_contract_block).encode('utf8'))
                # print(b'msg%s' % new_contract_hash.encode('utf8'), tornado.escape.json_encode(new_contract_block).encode('utf8'))
                db.put(b'chain%s' % msg_receiver.encode('utf8'), new_contract_hash.encode('utf8'))
                # print(b'chain%s' % msg_receiver.encode('utf8'), new_contract_hash.encode('utf8'))

                subchains_to_block[msg_receiver] = new_contract_hash

        # check the main chain history to avoid same contract address
        # since the subchain is sharding, which may not existing in KV db

        if last_highest_block_height + 1 == highest_block_height:
            last_hash_proofs = hash_proofs
        else:
            last_hash_proofs = set()
        hash_proofs = set()
        last_highest_block_height = highest_block_height

    elif highest_block_height < height - 1:
        # no, pk = identity.split(":")
        # if int(no) not in nodes_to_fetch:

        # need to fetch the missing block
        print('need to fetch the missing block', identity, int(identity[2:], 16))
        nodes_to_fetch.add(bin(int(identity[2:], 16))[2:].zfill(160))
        worker_thread_mining = False

# @tornado.gen.coroutine
def new_chain_proof(seq):
    global nodes_to_fetch
    global last_highest_block_height
    global hash_proofs
    global last_hash_proofs

    _msg_header, block_hash, prev_hash, height, nonce, difficulty, identity, data, timestamp, txid = seq
    # validate
    # check difficulty
    # print('new_chain_proof', last_highest_block_height, height)

    db = database.get_conn()
    # try:
    db.put(b'block%s' % block_hash.encode('utf8'), tornado.escape.json_encode(data).encode('utf8'))
    # except Exception as e:
    #     print("new_chain_proof Error: %s" % e)

    # print(last_highest_block_height, height, identity)
    # if highest_block_height + 1 < height:
    #     no, pk = identity.split(":")
    #     if int(no) not in nodes_to_fetch:
    #         nodes_to_fetch.add(int(no))

    # if last_highest_block_height != highest_block_height:
    #     if last_highest_block_height + 1 == highest_block_height:
    #         last_hash_proofs = hash_proofs
    #     else:
    #         last_hash_proofs = set()
    #     hash_proofs = set()
    #     # last_highest_block_height = highest_block_height

    # if highest_block_height + 1 == height:
    #     hash_proofs.add(tuple([block_hash, height]))

    # print('hash_proofs', hash_proofs)
    # print('last_hash_proofs', last_hash_proofs)

# @tornado.gen.coroutine
def new_subchain_block(seq):
    # global subchains_to_block
    _msg_header, msg_hash, prev_hash, sender, receiver, height, data, timestamp, signature = seq
    if setting.SHARDING:
        sender_bin = bin(int(sender[2:], 16))[2:].zfill(160)
        # print('current_nodeid', tree.current_nodeid, sender_bin)
        if not sender_bin.startswith(tree.current_nodeid):
            return

    assert sender.startswith('0x') and len(sender) == 42
    assert (receiver.startswith('0x') or receiver.startswith('1x')) and (len(receiver) == 42 or len(receiver) == 2) #valid address or empty to create contract
    # validate
    # check current main chain block state, find the subchain blocks until then, check the valdation
    # need to ensure current subchains_block[sender] is the ancestor of block_hash
    # print('new_subchain_block', block_hash, prev_hash, sender, receiver, height, data, timestamp, signature)
    # subchains_block[sender] = block_hash

    # sig = eth_keys.keys.Signature(eth_utils.hexadecimal.decode_hex(signature))
    # pk = sig.recover_public_key_from_msg_hash(eth_utils.hexadecimal.decode_hex(block_hash))
    # print('sig', pk)
    # print('id', pk.to_checksum_address(), sender)

    # http_client = tornado.httpclient.AsyncHTTPClient()
    # url = "http://127.0.0.1:7001/recover_public_key_from_msg_hash?signature=%s&hash=%s" % (signature, block_hash)
    # try:
    #     response = yield http_client.fetch(url, connect_timeout=60, request_timeout=60)#, method="POST", body=tornado.escape.json_encode(data)
    # except:
    #     pass

    db = database.get_conn()
    if prev_hash == '0'*64:
        prev_msgstate = {}
    else:
        prev_msgstate_json = db.get(b'msgstate_%s' % prev_hash.encode('utf8'))
        # print('prev_msgstate_json', prev_msgstate_json)
        prev_msgstate = tornado.escape.json_decode(prev_msgstate_json)

    # print('prev_msgstate', prev_msgstate)
    # print('data', data)
    msgstate = stf.subchain_stf(prev_msgstate, data)
    # print('msgstate', msgstate)
    msgstate_json = tornado.escape.json_encode(msgstate)
    # print('msgstate_json', msgstate_json)
    db.put(b'msgstate_%s' % msg_hash.encode('utf8'), msgstate_json.encode('utf8'))

    # verify
    # if data.get('type') == 'new_asset':
    #     block_hash = db.get(b'chain')
    #     blockstate_json = db.get(b'blockstate_%s' % block_hash)
    #     blockstate = tornado.escape.json_decode(blockstate_json)
    #     print('blockstate', blockstate)
    #     assert data['name'] not in blockstate.get('tokens', {})


    # try:
    db.put(b'msg%s' % msg_hash.encode('utf8'), tornado.escape.json_encode([msg_hash, prev_hash, sender, receiver, height, data, timestamp, signature]).encode('utf8'))
    assert len(sender) == 42
    db.put(b'chain%s' % sender.encode('utf8'), msg_hash.encode('utf8'))
    # get tx pool, if already exists, override only when the height is higher than current
    # when new block generated, the confirmed subchain block will be removed
    db.put(('pool%s_%s' % (sender, msg_hash)).encode('utf8'), ('%s_%s' % (height, prev_hash)).encode('utf8'))
    # except Exception as e:
    #     print("new_subchain_block Error: %s" % e)

def new_tempchain_block(seq):
    # global subchains_to_block
    print('new_tempchain_block', seq)
    _msg_header, msg_hash, prev_hash, sender, height, data, timestamp, signature = seq
    # msg_hash sender signature for validate
    print('new_tempchain_block data', data)
    print('channel_id', data['channel_id'])
    channel_id = data['channel_id']

    db = database.get_conn()
    db.put(b'tempmsg%s' % msg_hash.encode('utf8'), tornado.escape.json_encode([msg_hash, prev_hash, sender, height, data, timestamp, signature]).encode('utf8'))
    # db.put(b'tempmsg_state_%s' % msg_hash.encode('utf8'), b'')
    db.put(b'tempchain%s' % channel_id.encode('utf8'), msg_hash.encode('utf8'))

def get_recent_longest(highest_block_hash):
    db = database.get_conn()
    block_hash = highest_block_hash
    recent_longest = []
    for i in range(setting.BLOCK_DIFFICULTY_CYCLE):
        block_json = db.get(b'block%s' % block_hash)
        if block_json:
            block = tornado.escape.json_decode(block_json)
            block_hash = block[PREV_HASH].encode('utf8')
            recent_longest.append(block)
        else:
            break
    return recent_longest

def get_highest_block():
    db = database.get_conn()
    highest_block = None
    highest_block_height = 0
    highest_block_hash = db.get(b"chain")
    if highest_block_hash:
        block_json = db.get(b'block%s' % highest_block_hash)
        if block_json:
            block = tornado.escape.json_decode(block_json)
            highest_block_height = block[HEIGHT]
    else:
        highest_block_hash = b'0'*64
    return highest_block_height, highest_block_hash, highest_block

class GetHighestBlockHashHandler(tornado.web.RequestHandler):
    def get(self):
        highest_block_height, highest_block_hash, _ = get_highest_block()

        self.finish({'hash': highest_block_hash.decode('utf8'), 'height': highest_block_height})

class GetHighestBlockStateHandler(tornado.web.RequestHandler):
    def get(self):
        db = database.get_conn()
        block_hash = db.get(b'chain')
        blockstate_json = db.get(b'blockstate_%s' % block_hash)
        self.finish(blockstate_json)

class GetBlockHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        db = database.get_conn()
        block_json = db.get(b'block%s' % block_hash.encode('utf8'))
        if block_json:
            self.finish({"block": tornado.escape.json_decode(block_json)})
        else:
            self.finish({"block": None})

class GetBlockStateHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        db = database.get_conn()
        block_json = db.get(b'blockstate_%s' % block_hash.encode('utf8'))
        if block_json:
            self.finish({"state": tornado.escape.json_decode(block_json)})
        else:
            self.finish({"state": None})

class GetSubchainBlockStateHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        db = database.get_conn()
        block_json = db.get(b'msgstate_%s' % block_hash.encode('utf8'))
        if block_json:
            self.finish({"state": tornado.escape.json_decode(block_json)})
        else:
            self.finish({"state": None})

class GetTempchainBlockStateHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        db = database.get_conn()
        block_json = db.get(b'tempmsgstate_%s' % block_hash.encode('utf8'))
        if block_json:
            self.finish({"state": tornado.escape.json_decode(block_json)})
        else:
            self.finish({"state": None})

# class GetProofHandler(tornado.web.RequestHandler):
#     def get(self):
#         proof_hash = self.get_argument("hash")
#         conn = database.get_conn()
#         c = conn.cursor()
#         c.execute("SELECT * FROM proof WHERE hash = ?", (proof_hash,))
#         proof = c.fetchone()
#         self.finish({"proof": proof[1:]})

class GetHighestSubchainBlockHashHandler(tornado.web.RequestHandler):
    def get(self):
        # TODO: fixed key 'chain0x0000' for rocksdb
        sender = self.get_argument('sender')
        assert sender.startswith('0x')
        assert len(sender) == 42
        db = database.get_conn()
        highest_block_hash = db.get(b'chain%s' % sender.encode('utf8'))
        if highest_block_hash:
            self.finish({"hash": highest_block_hash.decode('utf8')})
        else:
            self.finish({"hash": '0'*64})


class GetHighestSubchainBlockStateHandler(tornado.web.RequestHandler):
    def get(self):
        sender = self.get_argument('sender')
        db = database.get_conn()
        msg_hash = db.get(b'chain%s' % sender.encode('utf8'))
        msgstate_json = db.get(b'msgstate_%s' % msg_hash)
        # chat_master_pk
        self.finish(msgstate_json)


class GetHighestTempchainBlockHashHandler(tornado.web.RequestHandler):
    def get(self):
        # TODO: fixed key 'chain0x0000' for rocksdb
        chain = self.get_argument('chain')
        # assert sender.startswith('0x')
        # assert len(sender) == 42
        db = database.get_conn()
        highest_block_hash = db.get(b'tempchain%s' % chain.encode('utf8'))
        if highest_block_hash:
            self.finish({"hash": highest_block_hash.decode('utf8')})
        else:
            self.finish({"hash": '0'*64})

class GetSubchainBlockHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        db = database.get_conn()
        block_json = db.get(b'msg%s' % block_hash.encode('utf8'))
        if block_json:
            self.finish({"msg": tornado.escape.json_decode(block_json)})
        else:
            self.finish({"msg": None})

class GetTempchainBlockHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        db = database.get_conn()
        block_json = db.get(b'tempmsg%s' % block_hash.encode('utf8'))
        if block_json:
            self.finish({"msg": tornado.escape.json_decode(block_json)})
        else:
            self.finish({"msg": None})

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
        response = urllib.request.urlopen("http://%s:%s/get_highest_block_hash" % (host, port))
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
    block_hashes_to_playback = []
    while block_hash != '0'*64:
        block_json = db.get(b'block%s' % block_hash.encode('utf8'))
        blockstate_json = db.get(b'blockstate_%s' % block_hash.encode('utf8'))
        if block_json and blockstate_json:
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
        print('fetch_chain block', block[HASH], block[HEIGHT])

        # try:
        db.put(b'block%s' % block_hash.encode('utf8'), tornado.escape.json_encode(block).encode('utf8'))
        block_hashes_to_playback.append(block_hash)
        # except Exception as e:
        #     print('fetch_chain Error: %s' % e)
        block_hash = block[PREV_HASH]

    if block_hashes_to_playback:
        while block_hashes_to_playback:
            block_hash = block_hashes_to_playback.pop()
            response = urllib.request.urlopen('http://%s:%s/get_block?hash=%s' % (host, port, block_hash))
            result = tornado.escape.json_decode(response.read())
            block = result['block']
            prev_hash = block[PREV_HASH]
            if prev_hash == '0'*64:
                prev_blockstate = {}
            else:
                prev_blockstate_json = db.get(b'blockstate_%s' % prev_hash.encode('utf8'))
                if prev_blockstate_json:
                    prev_blockstate = tornado.escape.json_decode(prev_blockstate_json)
            data = block[DATA]
            blockstate = stf.chain_stf(prev_blockstate, data)
            db.put(b'blockstate_%s' % block_hash.encode('utf8'), tornado.escape.json_encode(blockstate).encode('utf8'))

            # print(block_hash, block[HEIGHT])


    return highest_block_hash.encode('utf8'), highest_block_height

if __name__ == '__main__':
    pass
