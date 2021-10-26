from __future__ import print_function

import os
# import subprocess
import time
# import socket
# import argparse
import random
# import uuid
# import base64
import hashlib
# import urllib
import json

import requests
# import ecdsa
import eth_keys


USER_NO = 10
count = 10
users = {}
subchain_blocks = []


def main():
    for n in range(USER_NO):
        user_sk = eth_keys.keys.PrivateKey(open("users/sk%s.key" % n, 'rb').read())
        users[n] = user_sk
        print("load key", n)

    for n in range(count):
        # user_nos = set(range(USER_NO))
        # i = random.choice(list(user_nos))
        sender_sk = random.choice(list(users.values()))
        # sender_vk = sender_sk.get_verifying_key()
        # sender = base64.b32encode(sender_vk.to_string()).decode("utf8")
        # sender = str(n*2)
        # sender = sender_sk.public_key.to_address()[2:]

        # j = random.choice(list(user_nos - set([i])))
        receiver_sk = random.choice(list(users.values()))
        # receiver_vk = receiver_sk.get_verifying_key()
        # receiver = base64.b32encode(receiver_vk.to_string()).decode("utf8")
        # receiver = receiver_sk.public_key.to_address()[2:]
        # receiver = str(n*2+1)

        amount = random.randint(1, 20)
        print('sender', sender_sk.public_key, 'receiver', receiver_sk.public_key)
        rsp = requests.get('http://127.0.0.1:9001/get_highest_subchain_block_hash?sender=%s' % sender_sk.public_key.to_checksum_address())
        prev_hash = rsp.json()['hash']
        print('prev_hash', prev_hash)
        rsp = requests.get('http://127.0.0.1:9001/get_subchain_block?hash=%s' % prev_hash)
        # print(rsp.json())
        block = rsp.json()['msg']
        print('prev_block', block)
        new_timestamp = time.time()
        if block:
            height = block[4]
            data = {'amount': amount}
        else:
            height = 0
            data = {'amount': amount}

        data_json = json.dumps(data)
        block_hash = hashlib.sha256((prev_hash + sender_sk.public_key.to_checksum_address() + receiver_sk.public_key.to_checksum_address() + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
        signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
        print('sender', sender_sk.public_key.to_checksum_address())
        print('receiver', receiver_sk.public_key.to_checksum_address())
        print('signature', signature)
        block = [block_hash, prev_hash, sender_sk.public_key.to_checksum_address(), receiver_sk.public_key.to_checksum_address(), height+1, data, new_timestamp, signature.to_hex()]
        print('block', json.dumps(block))
        rsp = requests.post('http://127.0.0.1:9001/new_subchain_block?sender=%s' % sender_sk.public_key.to_checksum_address(), json=block)
        # print("gen subchain block", block)


if __name__ == '__main__':
    main()