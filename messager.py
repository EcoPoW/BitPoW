from __future__ import print_function

import sys
import os
import time
import pprint
# import random
import string
# import base64
import hashlib
import json

import requests
# import ecdsa
import eth_keys

import stf

def main():
    if len(sys.argv) < 2:
        print('''help:
  messager.py key
  messager.py host
  messager.py port
  messager.py enable
  messager.py disable
''')
        return

    store_obj = {}
    try:
        with open('./.messager.json', 'r') as f:
            store_obj = json.loads(f.read())
            # pprint.pprint(store_obj)

    except:
        print('error')
        # return

    if sys.argv[1] in ['key', 'host', 'port']:
        store_obj[sys.argv[1]] = sys.argv[2]
        with open('./.messager.json', 'w') as f:
            f.write(json.dumps(store_obj))
        return

    elif sys.argv[1] == 'address':
        pass

    elif sys.argv[1] == 'enable':
        key = store_obj['key']
        host = store_obj['host']
        port = store_obj['port']

        sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
        sender = sender_sk.public_key.to_checksum_address()

        blockstate_hash = store_obj.get('blockstate_hash', '0'*64)
        blockstate_dict = store_obj.get('blockstate_dict', {})

        rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
        highest_subchain_hash = rsp.json()['hash']
        block_hash = highest_subchain_hash
        print('block_hash', block_hash)
        print('sender', sender)

        block_stack = []
        while block_hash != blockstate_hash:
            print('  block_hash', block_hash)
            rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
            subchain_block = rsp.json()['msg']
            # print('    block', subchain_block[5])
            if subchain_block is None:
                break
            block_stack.append(block_hash)
            block_hash = subchain_block[1]
            assert subchain_block[2] == sender
            data = subchain_block[6]
            # if subchain_block[4] == 1:
            #     break

        # print('block stack', block_stack)
        while block_stack:
            # if not block_stack:
            #     break
            block_hash = block_stack.pop()
            print(block_hash)
            rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
            subchain_block = rsp.json()['msg']
            msg = subchain_block[5]
            print('    block', subchain_block[4])
            print('    msg', subchain_block[5])
            print('    old', blockstate_dict)
            blockstate_dict = stf.subchain_stf(blockstate_dict, msg)
            print('    new', blockstate_dict)
            print('')

        data = {
            'type': 'chat_enable',
            'chat_master_pk': '',
            'version': 1
        }
        data_json = json.dumps(data)

        highest_subchain_block = rsp.json()['msg']
        if highest_subchain_block:
            height = highest_subchain_block[4]
            highest_prev_hash = highest_subchain_block[0]
        else:
            height = 0
            highest_prev_hash = '0'*64

        new_timestamp = time.time()
        receiver = '0x'
        block_hash = hashlib.sha256((highest_prev_hash + sender + receiver + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
        signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
        # print('signature', signature.to_hex())

        new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, signature.to_hex()]
        print(new_subchain_block)
        # rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)

    elif sys.argv[1] == 'disable':
        key = store_obj['key']
        host = store_obj['host']
        port = store_obj['port']

        sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
        sender = sender_sk.public_key.to_checksum_address()

        blockstate_hash = store_obj.get('blockstate_hash', '0'*64)
        blockstate_dict = store_obj.get('blockstate_dict', {})

        rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
        highest_subchain_hash = rsp.json()['hash']
        block_hash = highest_subchain_hash
        print('block_hash', block_hash)
        print('sender', sender)

        block_stack = []
        while block_hash != blockstate_hash:
            print('  block_hash', block_hash)
            rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
            subchain_block = rsp.json()['msg']
            # print('    block', subchain_block[5])
            if subchain_block is None:
                break
            block_stack.append(block_hash)
            block_hash = subchain_block[1]
            assert subchain_block[2] == sender
            data = subchain_block[6]
            # if subchain_block[4] == 1:
            #     break

        # print('block stack', block_stack)
        while block_stack:
            # if not block_stack:
            #     break
            block_hash = block_stack.pop()
            print(block_hash)
            rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
            subchain_block = rsp.json()['msg']
            msg = subchain_block[5]
            print('    block', subchain_block[4])
            print('    msg', subchain_block[5])
            print('    old', blockstate_dict)
            blockstate_dict = stf.subchain_stf(blockstate_dict, msg)
            print('    new', blockstate_dict)
            print('')

        data = {
            'type': 'chat_disable',
            'version': 1
        }
        data_json = json.dumps(data)

        highest_subchain_block = rsp.json()['msg']
        if highest_subchain_block:
            height = highest_subchain_block[4]
            highest_prev_hash = highest_subchain_block[0]
        else:
            height = 0
            highest_prev_hash = '0'*64

        new_timestamp = time.time()
        receiver = '0x'
        block_hash = hashlib.sha256((highest_prev_hash + sender + receiver + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
        signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
        # print('signature', signature.to_hex())

        new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, signature.to_hex()]
        print(new_subchain_block)
        rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
        print(rsp.text)


if __name__ == '__main__':
    main()
