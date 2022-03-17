from __future__ import print_function

import os
# import subprocess
import time
# import socket
# import argparse
import random
import uuid
# import base64
import hashlib
# import urllib
import json

import requests
# import ecdsa
import eth_keys


users = {}
subchain_blockhash = {}
send_queue = []


def main(width, count):
    f = open("users/sk.keys", 'rb')
    for n in range(width):
        user_sk = eth_keys.keys.PrivateKey(f.read(32))
        users[n] = user_sk
        # print("load key", n)


        sender_address = user_sk.public_key.to_checksum_address()
        rsp = requests.get('http://127.0.0.1:9001/get_highest_subchain_block_hash?sender=%s' % sender_address)
        prev_hash = rsp.json()['hash']
        # print('prev_hash', prev_hash)
        rsp = requests.get('http://127.0.0.1:9001/get_subchain_block?hash=%s' % prev_hash)
        block = rsp.json()['msg']
        # print('block', sender_address, block)
        subchain_blockhash[sender_address] = block
    f.close()

    # print(subchain_blockhash)
    rsp = requests.get('http://127.0.0.1:9001/get_highest_block_hash')
    block_hash_before_transactions = rsp.json()['hash']

    # print('')
    for n in range(count):
        sender_sk = random.choice(list(users.values()))
        sender_address = sender_sk.public_key.to_checksum_address()
        receiver_sk = random.choice(list(users.values()))
        # print('sender', sender_sk.public_key, 'receiver', receiver_sk.public_key)

        block = subchain_blockhash.get(sender_address)
        # print('prev_block', block)
        amount = random.randint(1, 20)
        new_timestamp = time.time()
        if block:
            height = block[4]
            prev_hash = block[0]
            data = {'amount': amount}
        else:
            height = 0
            prev_hash = '0'*64
            data = {'amount': amount}

        data_json = json.dumps(data)
        block_hash_obj = hashlib.sha256((prev_hash + sender_address + receiver_sk.public_key.to_checksum_address() + str(height+1) + data_json + str(new_timestamp)).encode('utf8'))
        block_hash = block_hash_obj.hexdigest()
        # block_hash_bytes = block_hash_obj.digest()
        # sig = sender_sk.sign_msg_hash(block_hash_bytes)
        # signature = sig.to_hex()
        signature = uuid.uuid4().hex
        # print('sender', sender_address)
        # print('receiver', receiver_sk.public_key.to_checksum_address())
        # print('signature', sig)
        block = [block_hash, prev_hash, sender_sk.public_key.to_checksum_address(), receiver_sk.public_key.to_checksum_address(), height+1, data, new_timestamp, signature]
        subchain_blockhash[sender_address] = block
        # print('block', json.dumps(block))
        send_queue.append((sender_address, block))
        # if n%100000 == 0:
        #     print(n)

    last_transaction_block_hash = block_hash
    while send_queue:
        # print(len(send_queue))
        blocks = []
        for i in range(1000):
            if send_queue:
                sender_address, block = send_queue.pop(0)
                blocks.append(block)
        # print(sender_address, block)
        rsp = requests.post('http://127.0.0.1:9001/new_subchain_block_batch', json=blocks)
        # print("gen subchain block", block)
        # print('')

    while True:
        rsp = requests.get('http://127.0.0.1:9001/get_highest_block_hash')
        block_hash = rsp.json()['hash']
        # print('prev_hash', prev_hash)
        rsp = requests.get('http://127.0.0.1:9001/get_block?hash=%s' % block_hash)
        block = rsp.json()['block']
        if last_transaction_block_hash in block[6]['subchains'].values():
            t_finished = block[7]
            # print('block', block[0], block[2], t_finished)
            block_hash = block[1]
            break
        time.sleep(1)

    while True:
        rsp = requests.get('http://127.0.0.1:9001/get_block?hash=%s' % block_hash)
        block = rsp.json()['block']
        if not block[6]['subchains']:
            t_start = block[7]
            # print('block', block[0], block[2], t_start)
            break
        block_hash = block[1]
        time.sleep(0.1)

    print(width, count, count/(t_finished - t_start))

if __name__ == '__main__':
    count = 1000000
    for width in range(20000, 100000, 1000):
        main(width, count)
