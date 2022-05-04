from __future__ import print_function

import os
import time
import random
import uuid
import hashlib
import json
import multiprocessing
# import subprocess
# import socket
# import argparse
# import base64
# import urllib

# import ecdsa
import requests
import eth_keys


users = {}
subchain_blockhash = {}


def main():
    f = open('miners/master.key', 'rb')
    user_sk = eth_keys.keys.PrivateKey(f.read(32))
    sender_address = user_sk.public_key.to_checksum_address()
    rsp = requests.get('http://127.0.0.1:9001/get_highest_subchain_block_hash?sender=%s' % sender_address)
    prev_hash = rsp.json()['hash']
    # print('prev_hash', prev_hash)
    rsp = requests.get('http://127.0.0.1:9001/get_subchain_block?hash=%s' % prev_hash)
    block = rsp.json()['msg']
    f.close()


    data = {
        'type': 'new_asset',
        'name': 'SHA',
        'amount': 10**15,
        'decimal': 0,
        'description': '',
        'bridges': {},
        'creator': sender_address
    }

    new_timestamp = time.time()
    if block:
        height = block[4]
        prev_hash = block[0]
    else:
        height = 0
        prev_hash = '0'*64

    data_json = json.dumps(data)
    block_hash_obj = hashlib.sha256((prev_hash + sender_address + '0x' + str(height+1) + data_json + str(new_timestamp)).encode('utf8'))
    block_hash = block_hash_obj.hexdigest()
    signature = uuid.uuid4().hex
    block = [block_hash, prev_hash, sender_address, '0x', height+1, data, new_timestamp, signature]
    rsp = requests.post('http://127.0.0.1:9001/new_subchain_block', json=block)

if __name__ == '__main__':
    main()
