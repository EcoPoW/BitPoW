from __future__ import print_function

import sys
import os
import time
import argparse
import random
import uuid
import base64
import hashlib
import json

import requests
import ecdsa


def main():
    parser = argparse.ArgumentParser(description="wallet.py --name=[your name] --host=[node host] --port=[node port]")
    parser.add_argument('--name')
    parser.add_argument('--host')
    parser.add_argument('--port')

    args = parser.parse_args()
    name = args.name
    host = args.host
    port = args.port

    blocks = set()
    proofs = set()

    sender_sk = ecdsa.SigningKey.from_pem(open("%s.pem" % name).read())
    sender_vk = sender_sk.get_verifying_key()
    sender = base64.b32encode(sender_vk.to_string()).decode("utf8")
    receiver = ''

    rsp = requests.get('http://%s:%s/get_highest_block' % (host, port))
    print(rsp.json())
    prev_hash = rsp.json()["hash"]
    while True:
        rsp = requests.get('http://%s:%s/get_block?hash=%s' % (host, port, prev_hash))
        block = rsp.json()["block"]
        print(block[2], block[0])
        if block[5] == sender:
            print('  block', 2**256/int(block[0], 16))
            blocks.add(block[0])
        data = json.loads(block[7])
        for proof in data["proofs"]:
            rsp = requests.get('http://%s:%s/get_proof?hash=%s' % (host, port, proof[0]))
            proof = rsp.json()["proof"]
            if proof[5] == sender:
                print('  proof', 2**256/int(proof[0], 16))
                # print(proof[2], proof[0])
                proofs.add(proof[0])
        prev_hash = block[1]
        if block[2] == 1:
            break
        print('-')

    rsp = requests.get('http://%s:%s/get_highest_subchain_block?sender=%s' % (host, port, sender))
    prev_hash = rsp.json()['hash']
    print('prev_hash', prev_hash)

    rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, prev_hash))
    print(rsp.json())
    block = rsp.json()['block']
    print('prev_block', block)
    new_timestamp = time.time()
    data = {'proofs': list(proofs), 'blocks': list(blocks)}
    if block:
        height = block[4]
    else:
        height = 0

    data_json = json.dumps(data)
    block_hash = hashlib.sha256((prev_hash + sender + receiver + str(height+1) + str(new_timestamp) + data_json).encode('utf8')).hexdigest()
    signature = base64.b32encode(sender_sk.sign(str(block_hash).encode("utf8"))).decode("utf8")
    print('signature', signature)
    subchain_block = [block_hash, prev_hash, sender, receiver, height+1, data, new_timestamp, signature]
    rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json=subchain_block)
    print("gen subchain block", subchain_block)


if __name__ == '__main__':
    main()