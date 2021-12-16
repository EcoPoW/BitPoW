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
import copy

import requests
# import ecdsa
import eth_keys


def state_transfer_function(state, msg):
    new_state = copy.deepcopy(state)
    if msg.get('type') == 'folder_storage':
        folder = msg.get('name')
        assert folder
        new_state.setdefault('folder_storage', {})
        current_folder = new_state['folder_storage'].setdefault(folder, {})
        # print('current folder', current_folder)
        if 'remove' in msg:
            remove_dict = msg['remove']
            for path, info in remove_dict.items():
                # print('remove', path, info)
                assert path in current_folder and info == current_folder[path]
                del current_folder[path]

        if 'add' in msg:
            add_dict = msg['add']
            for path, info in add_dict.items():
                # print('add', path, info)
                assert path not in current_folder
                current_folder[path] = info
        # print('fullstate dict', fullstate_dict)

    return new_state


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
        if sys.argv[1] in ['key', 'host', 'port', 'folder']:
            store_obj[sys.argv[1]] = sys.argv[2]
            with open('./store.json', 'w') as f:
                f.write(json.dumps(store_obj))
            return

        elif sys.argv[1] == 'add':
            fullstate_dict = store_obj.get('fullstate_dict', {})
            folder = store_obj['folder']

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

            print(chunks)
            store_obj.setdefault('add', {})[path_to_add] = {
                'chunks': chunks,
                'size': path_to_add_size
            }
            state_folders = fullstate_dict.setdefault('folder_storage', {})
            state_folder = state_folders.setdefault(folder, {})
            info_to_add = state_folder.get(path_to_add)
            if info_to_add:
                store_obj.setdefault('remove', {})[path_to_add] = info_to_add
            print(store_obj)
            with open('./store.json', 'w') as f:
                f.write(json.dumps(store_obj))
            return

        elif sys.argv[1] == 'remove':
            fullstate_dict = store_obj.get('fullstate_dict', {})
            folder = store_obj['folder']

            path_to_remove = sys.argv[2]
            chunks = []
            path_to_add_size = 0
            with open(path_to_remove, 'rb') as f:
                while True:
                    chunk = f.read(2**20*8)
                    if chunk:
                        chunks.append(hashlib.sha256(chunk).hexdigest())
                        path_to_add_size += len(chunk)
                    else:
                        break

            print(chunks)
            store_obj.setdefault('remove', {})[path_to_remove] = {
                'chunks': chunks,
                'size': path_to_add_size
            }
            # state_folders = fullstate_dict.setdefault('folder_storage', {})
            # state_folder = state_folders.setdefault(folder, {})
            # info_to_add = state_folder.get(path_to_add)
            # if info_to_add:
            #     store_obj.setdefault('remove', {})[path_to_add] = info_to_add
            print(store_obj)
            with open('./store.json', 'w') as f:
                f.write(json.dumps(store_obj))
            return

    elif len(sys.argv) == 2:
        if sys.argv[1] == 'status':
            add = store_obj.get('add', {})
            remove = store_obj.get('remove', {})

            print('add')
            pprint.pprint(add)
            print('remove')
            pprint.pprint(remove)

            for path in add:
                with open(path, 'rb') as f:
                    chunks = []
                    path_to_add_size = 0
                    while True:
                        chunk = f.read(2**20*8)
                        if chunk:
                            chunks.append(hashlib.sha256(chunk).hexdigest())
                            path_to_add_size += len(chunk)
                        else:
                            break
                print(path, chunks, path_to_add_size)

            return

        elif sys.argv[1] == 'sync':
            # will update local state and file if matched
            key = store_obj['key']
            host = store_obj['host']
            port = store_obj['port']
            folder = store_obj['folder']
            sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
            sender = sender_sk.public_key.to_checksum_address()
            fullstate_hash = store_obj.get('fullstate_hash', '0'*64)
            fullstate_dict = store_obj.get('fullstate_dict', {})

            rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
            highest_subchain_hash = rsp.json()['hash']
            block_hash = highest_subchain_hash
            print('sender', sender)
            block_stack = []
            while block_hash != fullstate_hash:
                # print('  block_hash', block_hash)
                rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
                subchain_block = rsp.json()['msg']
                # print('    data', subchain_block[5])
                # print('assert', subchain_block)
                if subchain_block is None:
                    break
                block_stack.append(block_hash)
                block_hash = subchain_block[1]
                assert subchain_block[2] == sender
                data = subchain_block[6]
                # if subchain_block[4] == 1:
                #     break

            print('block stack', block_stack)
            while block_stack:
                # if not block_stack:
                #     break
                block_hash = block_stack.pop()
                print(block_hash)
                rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
                subchain_block = rsp.json()['msg']
                msg = subchain_block[5]
                print('    msg', subchain_block[5])
                print('    old', fullstate_dict)
                fullstate_dict = state_transfer_function(fullstate_dict, msg)
                print('    new', fullstate_dict)
                print('')

            print('fullstate dict', fullstate_dict)
            store_obj['fullstate_dict'] = fullstate_dict
            store_obj['fullstate_hash'] = highest_subchain_hash
            if 'remove' in store_obj:
                del store_obj['remove']
            if 'add' in store_obj:
                del store_obj['add']
            with open('./store.json', 'w') as f:
                f.write(json.dumps(store_obj))
            return

        elif sys.argv[1] == 'reset':
            # reset file from chain at certain hash
            if 'remove' in store_obj:
                del store_obj['remove']
            if 'add' in store_obj:
                del store_obj['add']
            with open('./store.json', 'w') as f:
                f.write(json.dumps(store_obj))
            return

        elif sys.argv[1] == 'commit':
            # will not sync
            # will not commit if local state not matching latest state on chain
            key = store_obj['key']
            host = store_obj['host']
            port = store_obj['port']
            folder = store_obj['folder']
            add = store_obj.get('add')
            remove = store_obj.get('remove')
            sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
            sender = sender_sk.public_key.to_checksum_address()

            # chain_blocks = set()
            # chain_proofs = set()
            # subchain_blocks = set()
            # subchain_proofs = set()

            fullstate_hash = store_obj.get('fullstate_hash', '0'*64)
            fullstate_dict = store_obj.get('fullstate_dict', {})

            rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
            highest_subchain_hash = rsp.json()['hash']
            block_hash = highest_subchain_hash
            print('sender', sender)
            block_stack = []
            while block_hash != fullstate_hash:
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

            print('block stack', block_stack)
            while block_stack:
                # if not block_stack:
                #     break
                block_hash = block_stack.pop()
                print(block_hash)
                rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
                subchain_block = rsp.json()['msg']
                msg = subchain_block[5]
                print('    msg', subchain_block[5])
                print('    old', fullstate_dict)
                fullstate_dict = state_transfer_function(fullstate_dict, msg)
                print('    new', fullstate_dict)
                print('')

            # print('fullstate dict', fullstate_dict)
            data = {
                'type': 'folder_storage',
                'name': folder,
                'version': 1
            }
            if remove:
                data['remove'] = remove
            if add:
                data['add'] = add
            data_json = json.dumps(data)

            rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, highest_subchain_hash))
            highest_subchain_block = rsp.json()['msg']
            if highest_subchain_block:
                height = highest_subchain_block[4]
                highest_prev_hash = highest_subchain_block[0]
            else:
                height = 0
                highest_prev_hash = '0'*64

            new_timestamp = time.time()
            receiver = sender
            block_hash = hashlib.sha256((highest_prev_hash + sender + receiver + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
            signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
            # print('signature', signature.to_hex())
            try:
                new_fullstate_dict = state_transfer_function(fullstate_dict, data)
                new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, signature.to_hex()]
                rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
                new_fullstate_hash = new_subchain_block[0]
                store_obj['fullstate_dict'] = new_fullstate_dict
                store_obj['fullstate_hash'] = new_fullstate_hash

                # new_contract_address = '0x%s' % new_subchain_block[0]
                # print("new contract address", new_contract_address)
                print("new subchain block", new_subchain_block)

                if 'remove' in store_obj:
                    del store_obj['remove']
                if 'add' in store_obj:
                    del store_obj['add']

                with open('./store.json', 'w') as f:
                    f.write(json.dumps(store_obj))

            except AssertionError:
                print('failed')
                print(fullstate_dict)
                print(data)

            return

            # t0 = time.time()
            # for i in range(1):
            #     data = {
            #         'action': 'update',
            #         'crypto': 'AES_OFB',
            #         'iv': '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f',
            #         'remove': {
            #             'aes_encrypted_folder1': {
            #                 'aes_encrypted_file_path_and_name_in_hex': {
            #                     'chunks': [],
            #                     'size': (2**20)*11,
            #                     'time': ''
            #                 }
            #             }
            #         },
            #         'add': {
            #             'aes_encrypted_folder1': {
            #                 'aes_encrypted_file_path_and_name_in_hex': {
            #                     'chunks': [],
            #                     'size': (2**20)*11,
            #                     'time': ''
            #                 }
            #             }
            #         }
            #     }
            #     data_json = json.dumps(data)
            #     highest_prev_hash = new_subchain_block[0]
            #     height = new_subchain_block[4]
            #     new_timestamp = time.time()
            #     block_hash = hashlib.sha256((highest_prev_hash + sender + new_contract_address + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
            #     signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
            #     # print('signature', signature.to_hex())
            #     new_subchain_block = [block_hash, highest_prev_hash, sender, new_contract_address, height+1, data, new_timestamp, signature.to_hex()]
            #     rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
            #     # print("new subchain block", new_subchain_block)
            # print(time.time() - t0)

        elif sys.argv[1] == 'log':
            key = store_obj['key']
            host = store_obj['host']
            port = store_obj['port']

            sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
            sender = sender_sk.public_key.to_checksum_address()

            rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
            highest_subchain_hash = rsp.json()['hash']
            block_hash = highest_subchain_hash
            print('sender', sender)
            # block_stack = []
            while block_hash != '0'*64:
                print('  block_hash', block_hash)
                rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
                subchain_block = rsp.json()['msg']
                if subchain_block is None:
                    break
                print('    block', subchain_block[5])
                # block_stack.append(block_hash)
                block_hash = subchain_block[1]
                assert subchain_block[2] == sender
                data = subchain_block[6]
                # if subchain_block[4] == 1:
                #     break

            return

        elif sys.argv[1] == 'diff':
            return

    elif len(sys.argv) == 1:
        print('help')
        return

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
    # print('signature', signature.to_hex())
    new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, signature.to_hex()]
    rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
    new_contract_address = '0x%s' % new_subchain_block[0]
    print("new contract address", new_contract_address)
    print("  subchain block", new_subchain_block, '\n')

    t0 = time.time()
    for i in range(1):
        highest_prev_hash = new_subchain_block[0]
        height = new_subchain_block[4]
        new_timestamp = time.time()
        block_hash = hashlib.sha256((highest_prev_hash + sender + new_contract_address + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
        signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
        # print('signature', signature.to_hex())
        print("call contract address", new_contract_address)
        new_subchain_block = [block_hash, highest_prev_hash, sender, new_contract_address, height+1, data, new_timestamp, signature.to_hex()]
        rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
        print("  subchain block", new_subchain_block)
    print(time.time() - t0)

if __name__ == '__main__':
    main()
