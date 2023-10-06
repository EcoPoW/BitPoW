
# import sys
# import os
# import argparse
# import uuid
# import base64
# import threading
# import secrets
# import time
# import copy
import hashlib
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
import eth_tx
import console
import state
# import rpc
# import node
# import leader

import eth_keys
import eth_utils
import eth_account
# import rlp
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

# SENDER = 2
# RECEIVER = 3
MSG_TYPE = 2
MSG_TIMESTAMP = 3
MSG_DATA = 4
MSG_SIGNATURE = 5
REF_HASH = 6
REF_HEIGHT = 7

recent_longest = []
nodes_in_chain = {}

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
subchains_new_block_available = set()

# last_highest_block_height = 0
# hash_proofs = set()
# last_hash_proofs = set()

# subchains_to_block = {}
# tokens_to_block = {}
# aliases_to_block = {}
# balances_to_collect = {}


# @tornado.gen.coroutine
# def new_chain_block(seq):
#     global nodes_to_fetch
#     global recent_longest
#     global last_highest_block_height
#     global hash_proofs
#     global last_hash_proofs
#     global subchains_to_block
#     global tokens_to_block
#     global aliases_to_block
#     global balances_to_collect
#     _msg_header, block_hash, prev_hash, height, nonce, difficulty, identity, data, timestamp, signature, txid = seq

#     # validate hash
#     data_json = tornado.escape.json_encode(data)
#     assert block_hash == hashlib.sha256((prev_hash + str(height) + str(nonce) + str(difficulty) + identity + data_json + str(timestamp)).encode('utf8')).hexdigest()
#     # check difficulty

#     db = database.get_conn()
#     highest_block_hash = db.get(b'chain')
#     if highest_block_hash:
#         highest_block_json = db.get(b'block_%s' % highest_block_hash)
#         if highest_block_json:
#             highest_block = tornado.escape.json_decode(highest_block_json)
#             highest_block_height = highest_block[HEIGHT]
#     else:
#         highest_block_height = 0
#         highest_block_hash = b'0'*64

#     # print('new_chain_block', block_hash)
#     # validate signature
#     sig = eth_keys.keys.Signature(eth_utils.hexadecimal.decode_hex(signature))
#     pk = sig.recover_public_key_from_msg_hash(eth_utils.hexadecimal.decode_hex(block_hash))
#     # print('sig', pk)
#     # print('id', pk.to_checksum_address(), identity)
#     assert pk.to_checksum_address() == identity

#     # validate nonce
#     if highest_block_height >= height - 1: # and highest_block_hash.decode() == prev_hash
#         prev_blockstate = {}
#         blockstate = {}

#         if highest_block_height: # load prev full state
#             prev_blockstate_json = db.get(b'blockstate_%s' % prev_hash.encode('utf8'))
#             if prev_blockstate_json:
#                 prev_blockstate = tornado.escape.json_decode(prev_blockstate_json)
#                 # check/fetch subchains msg in detail, compare with prev blockstate, eg, balance
#                 # blockstate = prev_blockstate
#                 # blockstate.setdefault('nodes', {}).update(data.get('nodes', {}))
#                 # blockstate.setdefault('subchains', {}).update(data.get('subchains', {}))
#                 blockstate = stf.chain_stf(prev_blockstate, seq[1:])

#         # verify subchains
#         subchains = data.get('subchains', {})
#         print('subchains', subchains)
#         for address, confirmed_msg_hash in subchains.items():
#             print('full state subchains', blockstate.get('subchains', {}).get(address))
#             # print('prev full state subchains', prev_blockstate.get('subchains', {}).get(address))
#             msg_hash = blockstate.get('subchains', {}).get(address)
#             prev_msg_hash = msg_hash
#             # print(prev_blockstate)
#             last_confirmed_msg_hash = prev_blockstate.get('subchains', {}).get(address, '0'*64)
#             # print('last_confirmed_msg_hash', last_confirmed_msg_hash)
#             # verify messages on subchain
#             while True:
#                 msg_json = db.get(b'msg_%s' % prev_msg_hash.encode('utf8'))
#                 if not msg_json:
#                     continue
#                 msg = tornado.escape.json_decode(msg_json)
#                 # print('new_chain_block msg', address, msg)
#                 # if 'eth_raw_tx' in msg[MSG_DATA]:
#                 #     raw_tx = msg[MSG_DATA]['eth_raw_tx']
#                 #     tx, _tx_from, tx_to, _tx_hash = rpc.tx_info(raw_tx)
#                 #     balances_to_collect.setdefault(tx_to, set())
#                 #     balances_to_collect[tx_to].add(prev_msg_hash)

#                 address = msg[SENDER]
#                 sender_hash = msg[REF_HASH]
#                 pool_value = db.get(('pool_%s_%s' % (address, sender_hash)).encode('utf8'))
#                 print('pool', address, sender_hash)
#                 if pool_value:
#                     print('delete pool', address, sender_hash)
#                     db.delete(('pool%s_%s' % (address, sender_hash)).encode('utf8'))

#                 prev_msg_hash = msg[PREV_HASH]
#                 # print('new_chain_block msg parent hash', prev_msg_hash)
#                 if prev_msg_hash == '0'*64:
#                     break
#                 if prev_msg_hash == last_confirmed_msg_hash:
#                     # print('verify done', address, prev_msg_hash, last_confirmed_msg_hash)
#                     break

#         # data_clone['balances_to_collect'] = balances_to_collect
#         blockstate = stf.chain_stf(prev_blockstate, seq[1:])

#         db.put(b'blockstate_%s' % block_hash.encode('utf8'), tornado.escape.json_encode(blockstate).encode('utf8'))
#         # try:
#         db.put(b'block_%s' % block_hash.encode('utf8'), tornado.escape.json_encode(seq[1:]).encode('utf8'))
#         if highest_block_height == height - 1:
#             db.put(b'chain', block_hash.encode('utf8'))
#             recent_longest.insert(0, seq[1:])
#         # except Exception as e:
#         #     print("new_chain_block Error: %s" % e)

#         if len(recent_longest) > setting.BLOCK_DIFFICULTY_CYCLE:
#             recent_longest.pop()
#         highest_block_height = height

#         # prepare the data for mining next block
#         subchains_to_block = {}
#         tokens_to_block = {}
#         aliases_to_block = {}

#         # print('prev_blockstate', prev_blockstate)
#         prev_subchains_highest = {}
#         for contract_address, contract_hash in prev_blockstate.get('subchains', {}).items():
#             # print(contract_address, contract_hash)
#             msg_json = db.get(b'msg_%s' % contract_hash.encode('utf8'))
#             if not msg_json:
#                 continue
#             msg = tornado.escape.json_decode(msg_json)
#             # print(msg)
#             # print(msg[SENDER])
#             # print(msg[REF_HEIGHT], msg[REF_HASH])
#             msg_height, msg_hash = prev_subchains_highest.get(msg[SENDER], (0, '0'*64))
#             if msg[REF_HEIGHT] > msg_height:
#                 # print(msg_height, msg_hash)
#                 prev_subchains_highest[msg[SENDER]] = (msg[REF_HEIGHT], msg[REF_HASH])
#         print('prev_subchains_highest', prev_subchains_highest)

#         pool_address_pending = {}
#         it = db.iteritems()
#         it.seek(b'pool')
#         for pool_key, pool_value in it:
#             if len(subchains_to_block) >= 9400:
#                 break
#             # if len(subchains_to_block) >= 400:
#             #     break
#             if not pool_key.startswith(b'pool'):
#                 break
#             key_items = pool_key[4:].split(b'_')
#             if len(key_items) != 2:
#                 break
#             value_items = pool_value.split(b'_')
#             if len(value_items) != 2:
#                 break
#             msg_address, msg_hash = key_items
#             msg_height = int(value_items[0])
#             prev_msg_hash = value_items[1]
#             # print('pool_key', pool_key)
#             # print('pool_value', msg_address, msg_height, msg_hash, prev_msg_hash)
#             pool_address_pending.setdefault(msg_address, set())
#             pool_address_pending[msg_address].add((msg_height, msg_hash, prev_msg_hash))

#         contracts_to_interact = []
#         for msg_address, msgs_set in pool_address_pending.items():
#             _last_confirmed_msg_height, last_confirmed_msg_hash = prev_subchains_highest.get(msg_address.decode('utf8'), (0, '0'*64))
#             last_confirmed_msg_hash = last_confirmed_msg_hash.encode('utf8')
#             msgs = list(msgs_set)
#             msgs.sort()
#             # print('msgs', msgs)
#             for msg_height, msg_hash, prev_msg_hash in msgs:
#                 print(msg_height, prev_msg_hash, last_confirmed_msg_hash)
#                 if prev_msg_hash == last_confirmed_msg_hash:
#                     print('msg', msg_hash)
#                     msg_json = db.get(b'msg_%s' % msg_hash)
#                     print(msg_json)
#                     if not msg_json:
#                         continue
#                     msg = tornado.escape.json_decode(msg_json)
#                     print('new_chain_block msg', msg)

#                     if msg[MSG_DATA].get('type') == 'new_asset':
#                         # token = msg[MSG_DATA]['name']
#                         # tokens_to_block[token] = address
#                         address = msg[MSG_DATA]['creator']

#                     elif msg[MSG_DATA].get('type') == 'new_alias':
#                         alias = msg[MSG_DATA]['name']
#                         address = msg[MSG_DATA]['address']
#                         aliases_to_block[alias] = address

#                     # if msg[RECEIVER] == '1x':
#                     #     contracts_to_interact.append(msg[HASH])

#                     # if msg[RECEIVER].startswith('1x') and len(msg[RECEIVER]) == 42:
#                     #     contracts_to_interact.append(msg[HASH])

#                     last_confirmed_msg_hash = msg_hash

#         for i in contracts_to_interact:
#             print('contracts_to_interact', i)
#             msg_json = db.get(b'msg_%s' % i.encode('utf8'))
#             msg = tornado.escape.json_decode(msg_json)
#             # print(msg)

#             if msg[RECEIVER] == '1x':
#                 # new_contract_block
#                 # new_contract_address = '0x%s' % msg[HASH]
#                 msg_hash = msg[HASH]
#                 msg_sender = msg[SENDER]
#                 msg_height = msg[MSG_HEIGHT]
#                 msg_data = msg[MSG_DATA]
#                 # print('mining new_contract', msg_hash)
#                 # print('mining new_contract_address', new_contract_address)

#                 # new_timestamp = time.time()
#                 new_contract_hash = hashlib.sha256(('0'*64 + msg_sender + '' + str(1) + tornado.escape.json_encode(msg_data) + msg_hash + str(msg_height)).encode('utf8')).hexdigest()
#                 # contract_signature = tree.node_sk.sign_msg(str(new_contract_hash).encode("utf8"))
#                 # print('mining signature', contract_signature.to_hex())
#                 new_contract_block = [new_contract_hash, '0'*64, msg_sender, '', 1, msg_data, msg_hash, msg_height]
#                 new_contract_address = '1x%s' % new_contract_hash[:40]

#                 # msgstate = stf.subchain_stf({}, msg)
#                 # print('msgstate', msgstate)
#                 # msgstate_json = tornado.escape.json_encode(msgstate)
#                 # print('msgstate_json', msgstate_json)
#                 # db.put(b'msgstate_%s' % new_contract_hash.encode('utf8'), msgstate_json.encode('utf8'))

#                 db.put(b'msg_%s' % new_contract_hash.encode('utf8'), tornado.escape.json_encode(new_contract_block).encode('utf8'))
#                 db.put(b'chain_%s' % new_contract_address.encode('utf8'), new_contract_hash.encode('utf8'))

#                 subchains_to_block[new_contract_address] = new_contract_hash

#             elif len(msg[RECEIVER]) == 42 and msg[RECEIVER].startswith('1x'):
#                 print('new_chain_block msg to contract', msg)
#                 msg_hash = msg[HASH]
#                 msg_sender = msg[SENDER]
#                 msg_receiver = msg[RECEIVER]
#                 msg_height = msg[MSG_HEIGHT]
#                 msg_data = msg[MSG_DATA]
#                 # user_msg_hash = msg[REF_HASH]
#                 # user_msg_height = msg[REF_HEIGHT]

#                 contract_parent_hash = db.get(b'chain_%s' % msg_receiver.encode('utf8'))
#                 # print(b'chain%s' % msg_receiver.encode('utf8'))
#                 # print(contract_parent_hash)
#                 contract_block_json = db.get(b'msg_%s' % contract_parent_hash)
#                 contract_block = tornado.escape.json_decode(contract_block_json)
#                 contract_height = contract_block[MSG_HEIGHT] + 1
#                 # contract_parent_hash = contract_block[PREV_HASH]
#                 # contract_data = contract_block[MSG_DATA]

#                 # new_timestamp = time.time()
#                 new_contract_hash = hashlib.sha256((contract_parent_hash.decode('utf8') + msg_sender + '' + str(contract_height) + tornado.escape.json_encode(msg_data) + msg_hash + str(msg_height)).encode('utf8')).hexdigest()
#                 # contract_signature = tree.node_sk.sign_msg(str(new_contract_hash).encode("utf8"))
#                 # print('mining signature', contract_signature.to_hex())
#                 new_contract_block = [new_contract_hash, contract_parent_hash.decode('utf8'), msg_sender, '', contract_height, msg_data, msg_hash, msg_height]

#                 prev_msgstate_json = db.get(b'msgstate_%s' % contract_parent_hash)
#                 prev_msgstate = tornado.escape.json_decode(prev_msgstate_json)
#                 # msgstate = stf.subchain_stf(prev_msgstate, msg)
#                 # print('msgstate', msgstate)
#                 # msgstate_json = tornado.escape.json_encode(msgstate)
#                 # print('msgstate_json', msgstate_json)
#                 # print('new_contract_hash', new_contract_hash)
#                 # db.put(b'msgstate_%s' % new_contract_hash.encode('utf8'), msgstate_json.encode('utf8'))

#                 db.put(b'msg_%s' % new_contract_hash.encode('utf8'), tornado.escape.json_encode(new_contract_block).encode('utf8'))
#                 # print(b'msg%s' % new_contract_hash.encode('utf8'), tornado.escape.json_encode(new_contract_block).encode('utf8'))
#                 db.put(b'chain_%s' % msg_receiver.encode('utf8'), new_contract_hash.encode('utf8'))
#                 # print(b'chain%s' % msg_receiver.encode('utf8'), new_contract_hash.encode('utf8'))

#                 subchains_to_block[msg_receiver] = new_contract_hash

#         # check the main chain history to avoid same contract address
#         # since the subchain is sharding, which may not existing in KV db

#         if last_highest_block_height + 1 == highest_block_height:
#             last_hash_proofs = hash_proofs
#         else:
#             last_hash_proofs = set()
#         hash_proofs = set()
#         last_highest_block_height = highest_block_height

#     elif highest_block_height < height - 1:
#         # no, pk = identity.split(":")
#         # if int(no) not in nodes_to_fetch:

#         # need to fetch the missing block
#         print('need to fetch the missing block', identity, int(identity[2:], 16))
#         nodes_to_fetch.add(bin(int(identity[2:], 16))[2:].zfill(160))


def new_chain_header(seq):
    # console.log(seq)
    _header, block_hash, header_data, block_nonce, difficulty = seq
    txbody_hash = header_data['txbody_hash']
    statebody_hash = header_data['statebody_hash']
    height = header_data['height']
    data = [block_hash, header_data, block_nonce]
    data_json = tornado.escape.json_encode(data)
    db = database.get_conn()
    reversed_height = str(setting.REVERSED_NO-height).zfill(16)
    # print(('headerblock_%s_%s' % (reversed_height, block_hash)).encode('utf8'), data_json.encode('utf8'))
    db.put(('headerblock_%s_%s' % (reversed_height, block_hash)).encode('utf8'), data_json.encode('utf8'))

def new_chain_txbody(seq):
    # console.log(seq)
    _header, block_hash, height, data_json, _msgid = seq
    db = database.get_conn()
    reversed_height = str(setting.REVERSED_NO-height).zfill(16)
    print(('txbody_%s_%s' % (reversed_height, block_hash)).encode('utf8'), data_json.encode('utf8'))
    db.put(('txbody_%s_%s' % (reversed_height, block_hash)).encode('utf8'), data_json.encode('utf8'))

    # console.log('data_json', data_json)
    data = tornado.escape.json_decode(data_json)
    for i in data:
        console.log(i)
        subchain_addr, subchain_height, subchain_hash = i
        value = tornado.escape.json_encode({'hash': subchain_hash, 'height': subchain_height})
        console.log(('globalsubchain_%s_%s_%s' % (subchain_addr, reversed_height, block_hash)))
        db.put(('globalsubchain_%s_%s_%s' % (subchain_addr, reversed_height, block_hash)).encode('utf8'), value.encode('utf8'))

def new_chain_statebody(seq):
    # print('new_chain_statebody', seq)
    _header, block_hash, height, data_json, _msgid = seq
    db = database.get_conn()
    reversed_height = str(setting.REVERSED_NO-height).zfill(16)
    print(('statebody_%s_%s' % (reversed_height, block_hash)).encode('utf8'), data_json.encode('utf8'))
    db.put(('statebody_%s_%s' % (reversed_height, block_hash)).encode('utf8'), data_json.encode('utf8'))

    # console.log('new_chain_statebody', data_json)
    data = tornado.escape.json_decode(data_json)
    # for i in data:
        # print(i)
    state.merge(block_hash, data)

# @tornado.gen.coroutine
def new_subchain_block(seq):
    # global subchains_to_block
    global subchains_new_block_available
    _header, subchain_hash, prev_hash, tx_type, timestamp, tx_list, signature = seq
    if len(tx_list) == 8:
        receiver = tx_list[5]
        height = tx_list[1]
    else:
        receiver = tx_list[3]
        height = tx_list[0]
    print('new_subchain_block tx_list', tx_list)

    eth_tx_hash = eth_tx.hash_of_eth_tx_list(tx_list)
    signature_obj = eth_account.Account._keys.Signature(bytes.fromhex(signature[2:]))
    pubkey = signature_obj.recover_public_key_from_msg_hash(eth_tx_hash)
    sender = pubkey.to_checksum_address()
    print('new_subchain_block sender', sender)

    if setting.SHARDING:
        sender_bin = bin(int(sender[2:], 16))[2:].zfill(160)
        # print('current_nodeid', tree.current_nodeid, sender_bin)
        if not sender_bin.startswith(tree.current_nodeid):
            return

    assert sender.startswith('0x') and len(sender) == 42
    assert receiver.startswith('0x') and (len(receiver) == 42 or len(receiver) == 2) #valid address or empty to create contract

    db = database.get_conn()
    console.log(('subchain_%s_%s_%s' % (sender, str(setting.REVERSED_NO - height).zfill(16), subchain_hash)).encode('utf8'))
    db.put(('subchain_%s_%s_%s' % (sender.lower(), str(setting.REVERSED_NO - height).zfill(16), subchain_hash)).encode('utf8'), tornado.escape.json_encode([subchain_hash, prev_hash, tx_type, timestamp, tx_list, signature]).encode('utf8'))
    db.put(('tx_0x%s' % subchain_hash).encode('utf8'), ('subchain_%s_%s_%s' % (sender.lower(), str(setting.REVERSED_NO - height).zfill(16), subchain_hash)).encode('utf8'))
    subchains_new_block_available.add(sender)

# def get_recent_longest(highest_block_hash):
#     db = database.get_conn()
#     block_hash = highest_block_hash
#     recent_longest = []
#     for i in range(setting.BLOCK_DIFFICULTY_CYCLE):
#         block_json = db.get(b'block_%s' % block_hash)
#         if block_json:
#             block = tornado.escape.json_decode(block_json)
#             block_hash = block[PREV_HASH].encode('utf8')
#             recent_longest.append(block)
#         else:
#             break
#     return recent_longest

# def get_highest_block(): # to remove
#     db = database.get_conn()
#     highest_block = None
#     highest_block_height = 0

#     highest_block_hash = db.get(b"chain")
#     if highest_block_hash:
#         block_json = db.get(b'block_%s' % highest_block_hash)
#         if block_json:
#             block = tornado.escape.json_decode(block_json)
#             highest_block_height = block[HEIGHT]
#     else:
#         highest_block_hash = b'0'*64

#     return highest_block_height, highest_block_hash, highest_block


def get_latest_block_number():
    db = database.get_conn()
    it = db.iteritems()
    it.seek(('headerblock_').encode('utf8'))
    no = 0
    for k, v in it:
        # print('get_latest_block_number', k, v)
        if k.decode('utf8').startswith('headerblock_'):
            ks = k.decode('utf8').split('_')
            reverse_no = int(ks[1])
            no = setting.REVERSED_NO - reverse_no
        break
    return no

def get_block_hashes_by_number(no):
    db = database.get_conn()
    it = db.iteritems()
    hashes = []
    it.seek(('headerblock_%s' % str(setting.REVERSED_NO-no).zfill(16)).encode('utf8'))
    for k, v in it:
        # print('get_block_hashes_by_number', k, v)
        if k.decode('utf8').startswith('headerblock_%s' % str(setting.REVERSED_NO-no).zfill(16)):
            header = tornado.escape.json_decode(v)
            blockhash = header[0]
            hashes.append(blockhash)
        else:
            break
    return hashes

def get_block_header_by_hash(no, h):
    db = database.get_conn()
    header_json = db.get(('headerblock_%s_%s' % (str(setting.REVERSED_NO-no).zfill(16), h)).encode('utf8'))
    header = tornado.escape.json_decode(header_json)
    return header

def get_block_txbody_by_hash(no, h):
    db = database.get_conn()
    body_json = db.get(('txbody_%s_%s' % (str(setting.REVERSED_NO-no).zfill(16), h)).encode('utf8'))
    body = tornado.escape.json_decode(body_json)
    return body

def get_block_statebody_by_hash(no, h):
    db = database.get_conn()
    body_json = db.get(('statebody_%s_%s' % (str(setting.REVERSED_NO-no).zfill(16), h)).encode('utf8'))
    body = tornado.escape.json_decode(body_json)
    return body


class GetChainLatestHashHandler(tornado.web.RequestHandler):
    def get(self):
        #_highest_block_height, highest_block_hash, _ = get_highest_block()
        latest_block_height = get_latest_block_number()
        latest_block_hashes = get_block_hashes_by_number(latest_block_height)

        self.finish({'blockhashes': latest_block_hashes, 'height': latest_block_height})

class GetChainBlockHandler(tornado.web.RequestHandler):
    def get(self):
        block_height = self.get_argument('height')
        block_hash = self.get_argument('hash')

        header = get_block_header_by_hash(block_height, block_hash)
        print(header)
        txbody = get_block_txbody_by_hash(no, h)
        statebody = get_block_statebody_by_hash(no, h)
        self.finish({'tx':txbody, 'state':statebody})

class GetStateSubchainsHandler(tornado.web.RequestHandler):
    def get(self):
        block_height = self.get_argument('height')
        no = int(block_height)
        addrs = self.get_argument('addrs')
        db = database.get_conn()
        it = db.iteritems()

        results = {}
        for addr in addrs.split(','):
            # print('addr', addr)
            results[addr.lower()] = None
            it.seek(('globalsubchain_%s_%s' % (addr.lower(), str(setting.REVERSED_NO-no).zfill(16))).encode('utf8'))
            for k, v in it:
                # print('GetStateSubchainsHandler', k, v)
                if not k.decode('utf8').startswith('globalsubchain_%s_' % addr.lower()):
                    break
                results[addr.lower()] = tornado.escape.json_decode(v)
                break
        self.finish(results)

class GetStateContractsHandler(tornado.web.RequestHandler):
    def get(self):
        # block_hash = self.get_argument('hash')
        addr = self.get_argument('addr')
        block_height = self.get_argument('height', None)
        if block_height:
            no = int(block_height)
            self.write('<a href="/get_state_contracts?addr=%s&height=%s">Prev</a> ' % (addr, no-1))
            self.write('<a href="/get_state_contracts?addr=%s&height=%s">Next</a> ' % (addr, no+1))
            self.write('<br><br>')
        db = database.get_conn()
        it = db.iteritems()

        results = {}
        # it.seek(('globalstate_%s_' % addr.lower()).encode('utf8'))
        it.seek(('globalstate_%s_' % addr.lower()).encode('utf8'))
        for k, v in it:
            # print('GetStateSubchainsHandler', k.decode('utf8').split('_'), v)
            if not k.decode('utf8').startswith(('globalstate_%s_' % addr.lower())):
                break
            reversed_no = int(k.decode('utf8').split('_')[3])
            if block_height and setting.REVERSED_NO - reversed_no != no:
                continue
            self.write(k)
            self.write('<br>')
            self.write(v)
            self.write('<br><br>')

class GetPoolSubchainsHandler(tornado.web.RequestHandler):
    def get(self):
        global subchains_new_block_available
        db = database.get_conn()
        it = db.iteritems()
        results = {}

        for addr in subchains_new_block_available:
            print(addr)
            it.seek(('subchain_%s_' % addr.lower()).encode('utf8'))
            for subchain_key, subchain_value in it:
                if not subchain_key.decode('utf8').startswith('subchain_%s_' % addr.lower()):
                    break

                subchain_key_list = subchain_key.decode('utf8').split('_')
                reversed_height = int(subchain_key_list[2])
                count = setting.REVERSED_NO - reversed_height
                #assert count + 1 == tx_nonce
                results[addr.lower()] = [count, subchain_key_list[3]]
                break

        # print('GetPoolSubchainsHandler results', results)
        self.finish(results)


class GetPoolBlocksHandler(tornado.web.RequestHandler):
    def get(self):
        addr = self.get_argument('addr')
        from_no = self.get_argument('from_no', 0)
        #from_hash = self.get_argument('from_hash', '0'*64)
        to_no = self.get_argument('to_no', None)
        to_hash = self.get_argument('to_hash', None)

        db = database.get_conn()
        it = db.iteritems()
        results = {'blocks': []}

        if to_no and to_hash:
            reversed_to_no = setting.REVERSED_NO - int(to_no)
            console.log('GetPoolBlocksHandler', addr, str(reversed_to_no).zfill(16), to_hash)
            it.seek(('subchain_%s_%s_%s' % (addr.lower(), str(reversed_to_no).zfill(16), to_hash)).encode('utf8'))
        else:
            it.seek(('subchain_%s_' % (addr.lower(), )).encode('utf8'))

        for subchain_key, subchain_value in it:
            if not subchain_key.decode('utf8').startswith('subchain_%s_' % (addr.lower(), )):
                break
            ks = subchain_key.decode('utf8').split('_')
            current_no = setting.REVERSED_NO - int(ks[2])
            if current_no <= int(from_no):
                break

            print('GetPoolBlocksHandler', subchain_key, subchain_value)
            tx = tornado.escape.json_decode(subchain_value)
            results['blocks'].append(tx)

        self.finish(results)


# class GetSubchainBlockStateHandler(tornado.web.RequestHandler):
#     def get(self):
#         block_hash = self.get_argument("hash")
#         db = database.get_conn()
#         block_json = db.get(b'msgstate_%s' % block_hash.encode('utf8'))
#         if block_json:
#             self.finish({"state": tornado.escape.json_decode(block_json)})
#         else:
#             self.finish({"state": None})

# class GetHighestSubchainBlockHashHandler(tornado.web.RequestHandler):
#     def get(self):
#         # TODO: fixed key 'chain0x0000' for rocksdb
#         sender = self.get_argument('sender')
#         assert sender.startswith('0x')
#         assert len(sender) == 42
#         db = database.get_conn()
#         highest_block_hash = db.get(b'chain_%s' % sender.encode('utf8'))
#         if highest_block_hash:
#             self.finish({"hash": highest_block_hash.decode('utf8')})
#         else:
#             self.finish({"hash": '0'*64})


# class GetHighestSubchainBlockStateHandler(tornado.web.RequestHandler):
#     def get(self):
#         sender = self.get_argument('sender')
#         db = database.get_conn()
#         msg_hash = db.get(b'chain_%s' % sender.encode('utf8'))
#         msgstate_json = db.get(b'msgstate_%s' % msg_hash)
#         # chat_master_pk
#         self.finish(msgstate_json)

# class GetSubchainBlockHandler(tornado.web.RequestHandler):
#     def get(self):
#         block_hash = self.get_argument("hash")
#         db = database.get_conn()
#         block_json = db.get(b'msg_%s' % block_hash.encode('utf8'))
#         if block_json:
#             self.finish({"msg": tornado.escape.json_decode(block_json)})
#         else:
#             self.finish({"msg": None})

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
        response = urllib.request.urlopen("http://%s:%s/get_chain_latest" % (host, port))
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
        block_json = db.get(b'block_%s' % block_hash.encode('utf8'))
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
        db.put(b'block_%s' % block_hash.encode('utf8'), tornado.escape.json_encode(block).encode('utf8'))
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
            # data = block[DATA]
            blockstate = stf.chain_stf(prev_blockstate, block)
            db.put(b'blockstate_%s' % block_hash.encode('utf8'), tornado.escape.json_encode(blockstate).encode('utf8'))

            # print(block_hash, block[HEIGHT])

    return highest_block_hash.encode('utf8'), highest_block_height

if __name__ == '__main__':
    pass
