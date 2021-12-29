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
  wallet.py key
  wallet.py host
  wallet.py port
  wallet.py balance
  wallet.py create_token <token_name> [total_amount] (for test, 0 for unlimited)
  wallet.py create_storage_contract
  wallet.py create_smart_contract
  wallet.py create_name
''')
        return

    store_obj = {}
    try:
        with open('./.store.json', 'r') as f:
            store_obj = json.loads(f.read())
            # pprint.pprint(store_obj)

        # if not os.path.exists('./.chunks/'):
        #     os.mkdir('./.chunks/')

    except:
        print('error')
        # return

    if sys.argv[1] in ['key', 'host', 'port']:
        store_obj[sys.argv[1]] = sys.argv[2]
        with open('./.store.json', 'w') as f:
            f.write(json.dumps(store_obj))
        return

    elif sys.argv[1] == 'create_token':
        # token must be UPPER CASE
        token = sys.argv[2]
        assert token[0] not in string.digits
        assert token[0] in string.ascii_uppercase
        assert token == token.upper()
        amount = sys.argv[3]
        assert int(amount) > -1
        return

    elif sys.argv[1] == 'create_name':
        # name must be lower case
        name = sys.argv[2]
        assert name[0] not in string.digits
        assert name[0] in string.ascii_lowercase
        assert name == name.lower()

        return

    elif sys.argv[1] == 'create_storage_contract':
        # is a contract
        # set the balance and rate
        # set the balance
        return

    elif sys.argv[1] == 'create_smart_contract':
        return

    elif sys.argv[1] == 'balance':
        # check main chain, get main chain full state
        # check the subchain of user, get the subchain full state

        key = store_obj['key']
        host = store_obj['host']
        port = store_obj['port']

        # chain_blocks = set()
        # chain_proofs = set()
        # subchain_blocks = set()
        # subchain_proofs = set()

        # sender_sk = ecdsa.SigningKey.from_pem(open("%s.pem" % name).read())
        sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
        sender = sender_sk.public_key.to_checksum_address()
        receiver = sender

        rsp = requests.get('http://%s:%s/get_highest_block_hash' % (host, port))
        print(rsp.json())
        highest_block_hash = rsp.json()["hash"]
        highest_block_height = rsp.json()["height"]

        chain_hash_every_100 = store_obj.get('chain_hash_every_100', {})
        block_hash = highest_block_hash
        # scan main chain
        while True:
            rsp = requests.get('http://%s:%s/get_block?hash=%s' % (host, port, block_hash))
            chain_block = rsp.json()["block"]
            if chain_block is None:
                break
            height = str(chain_block[2])
            if chain_block[2] % 100 == 0:
                print(height, block_hash)
                if height in chain_hash_every_100:
                    break
                chain_hash_every_100[height] = block_hash

            block_hash = chain_block[1]
            if chain_block[2] == 1:
                break

        # pprint.pprint(chain_hash_every_100)
        store_obj['chain_hash_every_100'] = chain_hash_every_100

        state = {}
        chain_fullstate_every_100 = store_obj.get('chain_fullstate_every_100', {})
        i = 0
        for i in range(100, highest_block_height, 100):
            print('>', i, chain_hash_every_100[str(i)])
            if str(i) in chain_fullstate_every_100:
                state = chain_fullstate_every_100[str(i)]
                print('load state', state)
                continue

            block_hash = chain_hash_every_100[str(i)]
            stack = []
            for j in range(100):
                rsp = requests.get('http://%s:%s/get_block?hash=%s' % (host, port, block_hash))
                chain_block = rsp.json()["block"]
                if chain_block is None:
                    break

                stack.append(chain_block)
                block_hash = chain_block[1]
            print(len(stack))

            while stack:
                block = stack.pop()
                state = stf.chain_stf(state, block[6])
                # print(block[2])
                if block[2] % 100 == 0:
                    print('save state', block[2])
                    chain_fullstate_every_100[str(block[2])] = state

        store_obj['chain_fullstate_every_100'] = chain_fullstate_every_100
        with open('./.store.json', 'w') as f:
            f.write(json.dumps(store_obj))

        print('highest_block_height', highest_block_height)
        stack = []
        block_hash = highest_block_hash
        for j in range(i, highest_block_height):
            print(j, block_hash)
            rsp = requests.get('http://%s:%s/get_block?hash=%s' % (host, port, block_hash))
            chain_block = rsp.json()["block"]
            # print(chain_block)
            if chain_block is None:
                break

            stack.append(chain_block)
            block_hash = chain_block[1]
            # print(len(stack))

        while stack:
            block = stack.pop()
            # print('>>> state', state)
            print('<<< block', block[6])
            state = stf.chain_stf(state, block[6])
            print('== new state', state)

        return
            # break

            # data = chain_block[6]
            # print(chain_block)

            # turn my proof to money
            # for proof in data["proofs"]:
            #     rsp = requests.get('http://%s:%s/get_proof?hash=%s' % (host, port, proof[0]))
            #     proof = rsp.json()["proof"]
            #     if proof[5] == sender:
            #         print('  proof', 2**256/int(proof[0], 16))
            #         # print(proof[2], proof[0])
            #         chain_proofs.add(proof[0])

            # check the subchains confirmed by main chain
            # for sender_account, msg_hash in data.get("subchains", {}).items():
            #     rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, msg_hash))
            #     # print('  subchain block', rsp.json()['msg'])
            #     print('  subchain', sender_account, msg_hash, rsp.json()['msg'][4])

            #     # check each subchain all the way to see if any message/transaction sent to me?


        rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
        highest_subchain_hash = rsp.json()['hash']
        block_hash = highest_subchain_hash
        print('sender', sender)
        print('block_hash', block_hash)
        while True:
            rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
            # print(rsp.json())
            subchain_block = rsp.json()['msg']
            print('assert', subchain_block)
            if subchain_block is None:
                break
            block_hash = subchain_block[1]
            assert subchain_block[2] == sender
            data = subchain_block[6]
            subchain_blocks.update(data.get("blocks", []))
            subchain_proofs.update(data.get("proofs", []))
            # print(subchain_block[4])
            if subchain_block[4] == 1:
                break
            # print('-')

        return


    amount = 0
    proofs = chain_proofs - subchain_proofs
    for hash in proofs:
        amount += int(2**256/int(hash, 16))
    blocks = chain_blocks - subchain_blocks
    for hash in blocks:
        amount += int(2**256/int(hash, 16))
    data = {'proofs': list(proofs), 'blocks': list(blocks), "amount": amount}
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
    block_hash = hashlib.sha256((highest_prev_hash + sender + receiver + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
    signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
    print('signature', signature.to_hex())
    new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, signature.to_hex()]
    rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
    print("new subchain block", new_subchain_block)


if __name__ == '__main__':
    main()
