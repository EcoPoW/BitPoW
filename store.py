from __future__ import print_function

# import sys
# import os
import time
import argparse
# import random
# import uuid
# import base64
import hashlib
import json

import requests
# import ecdsa
import eth_keys


def main():
    '''
    
    '''
    parser = argparse.ArgumentParser(description="wallet.py --key=[your name] --host=[node host] --port=[node port]")
    parser.add_argument('--key')
    parser.add_argument('--host')
    parser.add_argument('--port')

    args = parser.parse_args()
    key = args.key
    host = args.host
    port = args.port

    chain_blocks = set()
    chain_proofs = set()
    subchain_blocks = set()
    subchain_proofs = set()

    # sender_sk = ecdsa.SigningKey.from_pem(open("%s.pem" % name).read())
    sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
    sender = sender_sk.public_key.to_checksum_address()


    # rsp = requests.get('http://%s:%s/get_highest_block_hash' % (host, port))
    # print(rsp.json())
    # prev_hash = rsp.json()["hash"]

    # # scan main chain
    # while True:
    #     # turn my block to money
    #     rsp = requests.get('http://%s:%s/get_block?hash=%s' % (host, port, prev_hash))
    #     chain_block = rsp.json()["block"]
    #     if chain_block is None:
    #         break
    #     print(chain_block[2], chain_block[0])
    #     if chain_block[5] == sender:
    #         print('  block', 2**256/int(chain_block[0], 16))
    #         chain_blocks.add(chain_block[0])
    #     data = chain_block[6]
    #     print(chain_block)

    #     # turn my proof to money
    #     for proof in data["proofs"]:
    #         rsp = requests.get('http://%s:%s/get_proof?hash=%s' % (host, port, proof[0]))
    #         proof = rsp.json()["proof"]
    #         if proof[5] == sender:
    #             print('  proof', 2**256/int(proof[0], 16))
    #             # print(proof[2], proof[0])
    #             chain_proofs.add(proof[0])

    #     # check the subchains confirmed by main chain
    #     for sender_account, msg_hash in data.get("subchains", {}).items():
    #         rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, msg_hash))
    #         # print('  subchain block', rsp.json()['msg'])
    #         print('  subchain', sender_account, msg_hash, rsp.json()['msg'][4])

    #         # check each subchain all the way to see if any message/transaction sent to me?

    #     prev_hash = chain_block[1]
    #     if chain_block[2] == 1:
    #         break
    #     # print('-')

    rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
    highest_subchain_hash = rsp.json()['hash']
    prev_hash = highest_subchain_hash
    print('sender', sender)
    while True:
        print('  prev_hash', prev_hash)
        rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, prev_hash))
        subchain_block = rsp.json()['msg']
        print('assert', subchain_block)
        if subchain_block is None:
            break
        prev_hash = subchain_block[1]
        assert subchain_block[2] == sender
        data = subchain_block[6]
        subchain_blocks.update(data.get("blocks", []))
        subchain_proofs.update(data.get("proofs", []))
        # print(subchain_block[4])
        if subchain_block[4] == 1:
            break

    # amount = 0
    # proofs = chain_proofs - subchain_proofs
    # for hash in proofs:
    #     amount += int(2**256/int(hash, 16))
    # blocks = chain_blocks - subchain_blocks
    # for hash in blocks:
    #     amount += int(2**256/int(hash, 16))
    # data = {'proofs': list(proofs), 'blocks': list(blocks), "amount": amount}
    data = {}
    data_json = json.dumps(data)
    receiver = '0x'

    rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, highest_subchain_hash))
    highest_subchain_block = rsp.json()['msg']
    if highest_subchain_block:
        height = highest_subchain_block[4]
        highest_prev_hash = highest_subchain_block[0]
    else:
        height = 0
        highest_prev_hash = '0'*64

    new_timestamp = time.time()
    block_hash = hashlib.sha256((highest_prev_hash + sender + receiver + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
    signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
    print('signature', signature.to_hex())
    new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, signature.to_hex()]
    rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
    print("new subchain block", new_subchain_block)


if __name__ == '__main__':
    main()
