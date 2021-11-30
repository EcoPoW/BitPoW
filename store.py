from __future__ import print_function

import sys
# import os
import time
# import argparse
# import cmdline
# import random
# import uuid
# import base64
import hashlib
import json
import pprint

import requests
# import ecdsa
import eth_keys


def main():
    '''
    
    '''
    # parser = argparse.ArgumentParser(usage='tool [command] [options]')
    # parser.add_argument('-k', '--key')
    # parser.add_argument('-H', '--host')
    # parser.add_argument('-P', '--port')
    # subparsers = parser.add_subparsers(title='Available commands', metavar='')
    # subparsers.add_parser('add', help='foo.')
    # subparsers.add_parser('remove', help='bar.')
    # subparsers.add_parser('status', help='bar.')
    # subparsers.add_parser('commit', help='bar.')
    # subparsers.add_parser('reset', help='bar.')

    # args = parser.parse_args()
    # key = args.key
    # host = args.host
    # port = args.port
    # status = args.status
    store_obj = {}
    try:
        with open('./store.json', 'r') as f:
            store_obj = json.loads(f.read())
            print(store_obj)
    except:
        pass

    if len(sys.argv) == 3:
        print(sys.argv)
        if sys.argv[1] in ['key', 'host', 'port']:
            store_obj[sys.argv[1]] = sys.argv[2]
            with open('./store.json', 'w') as f:
                f.write(json.dumps(store_obj))

        elif sys.argv[1] == 'add':
            path_to_add = sys.argv[2]
            chunks = []
            path_to_add_size = 0
            with open(path_to_add, 'rb') as f:
                while True:
                    chunk = f.read(2**20*8)
                    if chunk:
                        chunks.append(hashlib.sha256(chunk).hexdigest())
                        path_to_add_size += len(chunk)
                    else:
                        break

            store_obj.setdefault('add', {})[path_to_add] = {
                'chunks': chunks,
                'size': path_to_add_size
            }
            with open('./store.json', 'w') as f:
                f.write(json.dumps(store_obj))

        elif sys.argv[1] == 'remove':
            pass

    elif len(sys.argv) == 2:
        if sys.argv[1] == 'status':
            pprint.pprint(store_obj.get('add', {}))
            pprint.pprint(store_obj.get('del', {}))

        elif sys.argv[1] == 'reset':
            store_obj['add'] = {}
            store_obj['del'] = {}
            with open('./store.json', 'w') as f:
                f.write(json.dumps(store_obj))

        elif sys.argv[1] == 'commit':
            key = store_obj['key']
            host = store_obj['host']
            port = store_obj['port']
            sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
            sender = sender_sk.public_key.to_checksum_address()

            chain_blocks = set()
            chain_proofs = set()
            subchain_blocks = set()
            subchain_proofs = set()

            rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
            highest_subchain_hash = rsp.json()['hash']
            prev_hash = highest_subchain_hash
            print('sender', sender)
            while True:
                print('  prev_hash', prev_hash)
                rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, prev_hash))
                subchain_block = rsp.json()['msg']
                # print('assert', subchain_block)
                if subchain_block is None:
                    break
                prev_hash = subchain_block[1]
                assert subchain_block[2] == sender
                data = subchain_block[6]
                # subchain_blocks.update(data.get("blocks", []))
                # subchain_proofs.update(data.get("proofs", []))
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
            data = {
                'type': 'storage_contract',
                'version': 1
            }
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
            # print('signature', signature.to_hex())
            new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, signature.to_hex()]
            rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
            new_contract_address = '0x%s' % new_subchain_block[0]
            print("new contract address", new_contract_address)
            print("  subchain block", new_subchain_block)

            t0 = time.time()
            for i in range(1):
                data = {
                    'action': 'update',
                    'crypto': 'AES_OFB',
                    'iv': '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f',
                    'remove': {
                        'aes_encrypted_folder1': {
                            'aes_encrypted_file_path_and_name_in_hex': {
                                'chunks': [],
                                'size': (2**20)*11,
                                'time': ''
                            }
                        }
                    },
                    'add': {
                        'aes_encrypted_folder1': {
                            'aes_encrypted_file_path_and_name_in_hex': {
                                'chunks': [],
                                'size': (2**20)*11,
                                'time': ''
                            }
                        }
                    }
                }
                data_json = json.dumps(data)
                highest_prev_hash = new_subchain_block[0]
                height = new_subchain_block[4]
                new_timestamp = time.time()
                block_hash = hashlib.sha256((highest_prev_hash + sender + new_contract_address + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
                signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
                # print('signature', signature.to_hex())
                new_subchain_block = [block_hash, highest_prev_hash, sender, new_contract_address, height+1, data, new_timestamp, signature.to_hex()]
                rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
                # print("new subchain block", new_subchain_block)
            print(time.time() - t0)


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

if __name__ == '__main__':
    main()
