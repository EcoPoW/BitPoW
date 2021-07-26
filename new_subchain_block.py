from __future__ import print_function

import os
# import subprocess
import time
# import socket
# import argparse
import random
import uuid
import base64
import hashlib
import urllib
import json

import requests
import ecdsa


USER_NO = 10
count = 1
users = {}
subchain_blocks = []


def main():
    for n in range(USER_NO):
        user_sk = ecdsa.SigningKey.from_pem(open("users/sk%s.pem" % n).read())
        users[n] = user_sk
        print("load key", n)

    for n in range(count):
        # user_nos = set(range(USER_NO))
        # i = random.choice(list(user_nos))
        sender_sk = random.choice(list(users.values()))
        sender_vk = sender_sk.get_verifying_key()
        sender = base64.b32encode(sender_vk.to_string()).decode("utf8")
        # sender = str(n*2)

        # j = random.choice(list(user_nos - set([i])))
        receiver_sk = random.choice(list(users.values()))
        receiver_vk = receiver_sk.get_verifying_key()
        receiver = base64.b32encode(receiver_vk.to_string()).decode("utf8")
        # receiver = str(n*2+1)

        amount = random.randint(1, 20)
        print('sender', sender)
        rsp = requests.get('http://127.0.0.1:8001/get_highest_subchain_block?sender=%s' % sender)
        prev_hash = rsp.json()['hash']
        print('prev_hash', prev_hash)
        rsp = requests.get('http://127.0.0.1:8001/get_subchain_block?hash=%s' % prev_hash)
        print(rsp.json())
        block = rsp.json()['block']
        print('prev_block', block)
        new_timestamp = time.time()
        if block:
            height = block[4]
            data = {'amount': amount}
        else:
            height = 0
            data = {'amount': amount}

        data_json = json.dumps(data)
        block_hash = hashlib.sha256((prev_hash + sender + receiver + str(height+1) + str(new_timestamp) + data_json).encode('utf8')).hexdigest()
        signature = base64.b32encode(sender_sk.sign(str(block_hash).encode("utf8"))).decode("utf8")
        print('signature', signature)
        block = [block_hash, prev_hash, sender, receiver, height+1, data, new_timestamp, signature]
        rsp = requests.post('http://127.0.0.1:8001/new_subchain_block?sender=%s' % sender, json=block)
        print("gen subchain block", block)


if __name__ == '__main__':
    main()