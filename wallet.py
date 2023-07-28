
import sys
import os
import time
import pprint
import uuid
import string
import hashlib
import json
# import random
# import base64

import requests
import web3
# import eth_keys
# import ecdsa

import stf

def main():
    if len(sys.argv) < 2:
        print('''help:
  wallet.py key
  wallet.py host
  wallet.py port
  wallet.py balance
  wallet.py create_asset <token_name> [total_amount] (for test, 0 for unlimited)
  wallet.py create_storage_contract
''')
        return

    store_obj = {}
    try:
        with open('./.wallet.json', 'r') as f:
            store_obj = json.loads(f.read())
            # pprint.pprint(store_obj)

        # if not os.path.exists('./.chunks/'):
        #     os.mkdir('./.chunks/')

    except:
        print('error')
        # return

    if sys.argv[1] in ['key', 'host', 'port']:
        store_obj[sys.argv[1]] = sys.argv[2]
        with open('./.wallet.json', 'w') as f:
            f.write(json.dumps(store_obj))
        return

    key = store_obj['key']
    host = store_obj['host']
    port = store_obj['port']

    if sys.argv[1] == 'create_asset':
        # token must be UPPER CASE
        token = sys.argv[2]
        assert token[0] not in string.digits
        assert token == token.upper()

        address = sys.argv[3]

    elif sys.argv[1] == 'create_asset_contract':
        amount = int(sys.argv[2])
        assert amount >= 0
        try:
            decimal = int(sys.argv[3])
        except:
            decimal = 0

        # sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
        # sender_address = sender_sk.public_key.to_checksum_address()
        account = web3.eth.Account.from_key(open(key, 'r').read().strip())
        sender_address = account.address

        rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender_address))
        prev_hash = rsp.json()['hash']
        # print('prev_hash', prev_hash)
        rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, prev_hash))
        block = rsp.json()['msg']

        data = {
            'type': 'new_asset',
            'amount': amount,
            'decimal': decimal,
            # 'name': token,
            # 'description': '',
            # 'bridges': {},
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
        block_hash_obj = hashlib.sha256((prev_hash + sender_address + '1x' + str(height+1) + data_json + str(new_timestamp)).encode('utf8'))
        block_hash = block_hash_obj.hexdigest()
        signature = uuid.uuid4().hex
        block = [block_hash, prev_hash, sender_address, '1x', height+1, data, new_timestamp, signature]
        rsp = requests.post('http://%s:%s/new_subchain_block' % (host, port), json=block)

        return

    elif sys.argv[1] == 'create_storage_contract':
        # is a contract
        # set the balance and rate
        # set the balance

        # sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
        # sender = sender_sk.public_key.to_checksum_address()
        account = web3.eth.Account.from_key(open(key, 'r').read().strip())
        sender = account.address
        # receiver = sender
        receiver = '0x'

        rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender))
        highest_subchain_hash = rsp.json()['hash']
        block_hash = highest_subchain_hash
        print('sender', sender)
        print('block_hash', block_hash)
        while True:
            rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, block_hash))
            # print(rsp.json())
            subchain_block = rsp.json()['msg']
            print('subchain_block', subchain_block)
            if subchain_block is None:
                break
            block_hash = subchain_block[1]
            assert subchain_block[2] == sender
            data = subchain_block[6]
            # subchain_blocks.update(data.get("blocks", []))
            # subchain_proofs.update(data.get("proofs", []))
            # print(subchain_block[4])
            if subchain_block[4] == 1:
                break


        rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, highest_subchain_hash))
        highest_subchain_block = rsp.json()['msg']
        if highest_subchain_block:
            height = highest_subchain_block[4]
            highest_prev_hash = highest_subchain_block[0]
        else:
            height = 0
            highest_prev_hash = '0'*64

        # data = {'proofs': list(proofs), 'blocks': list(blocks), "amount": amount}
        data = {}
        data_json = json.dumps(data)

        new_timestamp = time.time()
        block_digest = hashlib.sha256((highest_prev_hash + sender + receiver + str(height+1) + data_json + str(new_timestamp)).encode('utf8'))
        block_hash = block_digest.hexdigest()
        # signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
        sign_msg = account.signHash(block_digest.digest())
        print('signature', signature.to_hex())

        new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, sign_msg.signature.hex()]
        rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
        print("new subchain block", new_subchain_block)


        return

    elif sys.argv[1] == 'balance':
        # check main chain, get main chain full state
        # check the subchain of user, get the subchain full state

        contract = sys.argv[2]

        account = web3.eth.Account.from_key(open(key, 'r').read().strip())
        sender = account.address
        receiver = sender

        rsp = requests.get('http://%s:%s/get_highest_subchain_block_state?sender=%s' % (host, port, contract))
        print(rsp.text)
        print(rsp.json()['balances'][sender])
        return

    elif sys.argv[1] == 'send':
        contract = sys.argv[2]
        receiver = sys.argv[3]
        amount = sys.argv[4]

        account = web3.eth.Account.from_key(open(key, 'r').read().strip())
        sender_address = account.address

        rsp = requests.get('http://%s:%s/get_highest_subchain_block_hash?sender=%s' % (host, port, sender_address))
        prev_hash = rsp.json()['hash']
        # print('prev_hash', prev_hash)
        rsp = requests.get('http://%s:%s/get_subchain_block?hash=%s' % (host, port, prev_hash))
        block = rsp.json()['msg']

        data = {
            'type': 'send_asset',
            'amount': amount,
            # 'decimal': decimal,
            # 'name': token,
            # 'description': '',
            # 'bridges': {},
            'to': receiver
        }

        new_timestamp = time.time()
        if block:
            height = block[4]
            prev_hash = block[0]
        else:
            height = 0
            prev_hash = '0'*64

        data_json = json.dumps(data)
        block_hash_obj = hashlib.sha256((prev_hash + sender_address + receiver + str(height+1) + data_json + str(new_timestamp)).encode('utf8'))
        block_hash = block_hash_obj.hexdigest()
        signature = uuid.uuid4().hex
        block = [block_hash, prev_hash, sender_address, receiver, height+1, data, new_timestamp, signature]
        rsp = requests.post('http://%s:%s/new_subchain_block' % (host, port), json=block)

        return


    # amount = 0
    # proofs = chain_proofs - subchain_proofs
    # for hash in proofs:
    #     amount += int(2**256/int(hash, 16))
    # blocks = chain_blocks - subchain_blocks
    # for hash in blocks:
    #     amount += int(2**256/int(hash, 16))
    # data = {'proofs': list(proofs), 'blocks': list(blocks), "amount": amount}
    # data_json = json.dumps(data)


if __name__ == '__main__':
    main()
