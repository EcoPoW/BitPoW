from __future__ import print_function

import sys
import os
import time
import hashlib
import json
import base64
import secrets
import pprint

import requests
import eth_keys
import nacl.public
import ecdsa

import stf
import pre


def encrypt_nacl(public_key: bytes, data: bytes) -> bytes:
    emph_key = nacl.public.PrivateKey.generate()
    enc_box = nacl.public.Box(emph_key, nacl.public.PublicKey(public_key))
    data = base64.a85encode(data)
    ciphertext = enc_box.encrypt(data)
    return bytes(emph_key.public_key) + ciphertext

def decrypt_nacl(private_key: bytes, data: bytes) -> bytes:
    emph_key, ciphertext = data[:32], data[32:]
    box = nacl.public.Box(nacl.public.PrivateKey(private_key), nacl.public.PublicKey(emph_key))
    return base64.a85decode(box.decrypt(ciphertext))


def main():
    store_obj = {}
    try:
        with open('./.messager.json', 'r') as f:
            store_obj = json.loads(f.read())
            pprint.pprint(store_obj)

    except:
        print('error')
        # return

    key = store_obj['key']
    sender_sk = eth_keys.keys.PrivateKey(open(key, 'rb').read())
    sender = sender_sk.public_key.to_checksum_address()
    print('address', sender)

    if len(sys.argv) < 2:
        print('''help:
  messager.py key
  messager.py host
  messager.py port
  messager.py enable
  messager.py disable
''')
        return


    if sys.argv[1] in ['key', 'host', 'port']:
        store_obj[sys.argv[1]] = sys.argv[2]
        with open('./.messager.json', 'w') as f:
            f.write(json.dumps(store_obj))
        return

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

        chat_master_sk = nacl.public.PrivateKey.generate()
        chat_master_pk = chat_master_sk.public_key._public_key
        data = {
            'type': 'chat_enable',
            'chat_master_pk': base64.b16encode(chat_master_pk).decode('utf8'),
            'version': 1
        }
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
        receiver = '0x'
        block_hash = hashlib.sha256((highest_prev_hash + sender + receiver + str(height+1) + data_json + str(new_timestamp)).encode('utf8')).hexdigest()
        signature = sender_sk.sign_msg(str(block_hash).encode("utf8"))
        # print('signature', signature.to_hex())

        new_subchain_block = [block_hash, highest_prev_hash, sender, receiver, height+1, data, new_timestamp, signature.to_hex()]
        print(new_subchain_block)
        rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)

        store_obj['chat_master_sk'] = base64.b16encode(chat_master_sk._private_key).decode('utf8')
        with open('./.messager.json', 'w') as f:
            f.write(json.dumps(store_obj))

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

        if 'chat_master_sk' in store_obj:
            del store_obj['chat_master_sk']
            with open('./.messager.json', 'w') as f:
                f.write(json.dumps(store_obj))

    elif sys.argv[1] == 'request':
        print(store_obj)
        if 'chat_master_sk' not in store_obj or not store_obj['chat_master_sk']:
            print('chat_master_sk not found, try enable')
            return

        host = store_obj['host']
        port = store_obj['port']
        address = sys.argv[2]
        rsp = requests.get('http://%s:%s/chat_contact_new?address=%s' % (host, port, address))
        # print(rsp.text)
        target_chat_master_pk_hex = rsp.json()['chat_master_pk']
        # print(target_chat_master_pk_hex)
        target_chat_master_pk = nacl.public.PublicKey(base64.b16decode(target_chat_master_pk_hex))
        # print(target_chat_master_pk)


        # rsp = requests.post('http://%s:%s/new_subchain_block?sender=%s' % (host, port, sender), json = new_subchain_block)
        chat_master_sk_hex = store_obj['chat_master_sk']
        chat_master_sk = nacl.public.PrivateKey(base64.b16decode(chat_master_sk_hex))

        channel_id_bytes = secrets.token_bytes(32) # tempchain id
        channel_id = base64.b16encode(channel_id_bytes).decode('utf8')
        chat_temp_sk_bytes = secrets.token_bytes(32)
        chat_temp_sk = pre.load_sk(chat_temp_sk_bytes)
        chat_temp_pk = chat_temp_sk.public_key
        # print('chat_temp_sk', len(chat_temp_sk._private_key))
        knockdoor_data = ['KNOCKDOOR', channel_id, base64.b16encode(chat_temp_sk_bytes).decode('utf8'), time.time()]
        knockdoor_data_json = json.dumps(knockdoor_data)
        knockdoor_data_json_bytes = knockdoor_data_json.encode('utf8')
        knockdoor_data_encrypted = encrypt_nacl(target_chat_master_pk._public_key, knockdoor_data_json_bytes)
        # knockdoor_data_encrypted broadcast
        print(base64.b16encode(knockdoor_data_encrypted), len(knockdoor_data_encrypted))
        # or encode in QR code without encrypting
        print(knockdoor_data_json, len(knockdoor_data_json))

        # decrypted_data = decrypt_nacl(chat_master_sk._private_key, encrypted_data)
        # print(decrypted_data)

        chat_sk_bytes = secrets.token_bytes(32)
        chat_sk = pre.load_sk(chat_sk_bytes)
        chat_pk = chat_sk.public_key
        # print('chat_pk', len(chat_sk.public_key._public_key))
        sender = base64.b16encode(chat_pk.point.to_bytes()).decode('utf8')

        tempchain_init_data = {
            'type': 'chat',
            'channel_id': channel_id,
            'contacts': [sender],
            'temp_contacts': [base64.b16encode(chat_temp_pk.point.to_bytes()).decode('utf8')]
        }
        tempchain_init_data_json = json.dumps(tempchain_init_data)
        print(tempchain_init_data)

        # print(chat_sk.secret_multiplier)
        chat_sig_sk = ecdsa.keys.SigningKey.from_secret_exponent(chat_sk.secret_multiplier, ecdsa.SECP256k1)
        print('chat_sig_sk', chat_sig_sk)

        height = 0
        highest_prev_hash = '0'*64

        new_timestamp = time.time()
        block_hash = hashlib.sha256((highest_prev_hash + sender + str(height+1) + tempchain_init_data_json + str(new_timestamp)).encode('utf8'))
        signature = chat_sig_sk.sign_digest(block_hash.digest())
        # print('signature', signature)

        new_tempchain_block = [block_hash.hexdigest(), highest_prev_hash, sender, height+1, tempchain_init_data, new_timestamp, base64.b16encode(signature).decode('utf8')]
        print('new_tempchain_block', new_tempchain_block)
        rsp = requests.post('http://%s:%s/new_tempchain_block?chain=%s' % (host, port, channel_id), json = new_tempchain_block)

        store_obj.setdefault('channels', {})
        store_obj['channels'][channel_id] = base64.b16encode(chat_sk_bytes).decode('utf8')
        with open('./.messager.json', 'w') as f:
            f.write(json.dumps(store_obj))

    elif sys.argv[1] == 'accept':
        host = store_obj['host']
        port = store_obj['port']
        encrypted = sys.argv[2]

        chat_master_sk_hex = store_obj['chat_master_sk']
        chat_master_sk_bytes = base64.b16decode(chat_master_sk_hex)
        # chat_master_sk = nacl.public.PrivateKey(base64.b16decode(chat_master_sk_hex))
        knockdoor_data_json_bytes = base64.b16decode(encrypted)
        knockdoor_data_json = decrypt_nacl(chat_master_sk_bytes, knockdoor_data_json_bytes)
        knockdoor_data = json.loads(knockdoor_data_json)
        # print(knockdoor_data)
        assert knockdoor_data[0] == 'KNOCKDOOR'
        channel_id = knockdoor_data[1]

        chat_temp_sk_bytes = base64.b16decode(knockdoor_data[2])
        chat_temp_sk = pre.load_sk(chat_temp_sk_bytes)
        chat_temp_pk = chat_temp_sk.public_key
        print('chat_temp_pk', chat_temp_pk)
        chat_temp_sig_sk = ecdsa.keys.SigningKey.from_secret_exponent(chat_temp_sk.secret_multiplier, ecdsa.SECP256k1)
        chat_temp_sig_vk = chat_temp_sig_sk.verifying_key
        # print('chat_temp_sig_sk', chat_temp_sig_sk)
        # print('chat_temp_sig_vk', chat_temp_sig_vk)
        # print(chat_temp_pk == chat_temp_sig_vk.pubkey)

        chat_sk_bytes = secrets.token_bytes(32)
        chat_sk = pre.load_sk(chat_sk_bytes)
        chat_pk = chat_sk.public_key
        sender = base64.b16encode(chat_pk.point.to_bytes()).decode('utf8')

        rsp = requests.get('http://%s:%s/get_highest_tempchain_block_hash?chain=%s' % (host, port, channel_id))
        highest_subchain_hash = rsp.json()['hash']
        block_hash = highest_subchain_hash
        # print('block_hash', block_hash)
        # print('sender', sender)

        # block_stack = []
        # while block_hash != '0'*64:
        print('  block_hash', block_hash)
        rsp = requests.get('http://%s:%s/get_tempchain_block?hash=%s' % (host, port, block_hash))
        subchain_block = rsp.json()['msg']
        # print('    block', subchain_block)
        # if subchain_block is None:
        #     break
        # block_stack.append(block_hash)
        # block_hash = subchain_block[1]
        assert subchain_block[3] == 1
        data = subchain_block[4]
        print('    data', data)

        # if subchain_block[4] == 1:
        #     break

        # print('block stack', block_stack)
        # tempstate = {}
        # while block_stack:
        #     # if not block_stack:
        #     #     break
        #     block_hash = block_stack.pop()
        #     # print(block_hash)
        #     rsp = requests.get('http://%s:%s/get_tempchain_block?hash=%s' % (host, port, block_hash))
        #     subchain_block = rsp.json()['msg']
        #     msg = subchain_block[4]
        #     print('    block', subchain_block[0])
        #     print('    msg', subchain_block[4])
        #     print('    old', tempstate)
        #     tempstate = stf.subchain_stf(tempstate, msg)
        #     print('    new', tempstate)
        #     print('')

        tempchain_accept_data = {
            # 'type': 'chat',
            'channel_id': channel_id,
            'contacts': [sender],
            # 'temp_contacts': [base64.b16encode(chat_temp_pk.point.to_bytes()).decode('utf8')]
        }
        tempchain_accept_data_json = json.dumps(tempchain_accept_data)

        # print(chat_sk.secret_multiplier)
        chat_temp_sig_sk = ecdsa.keys.SigningKey.from_secret_exponent(chat_temp_sk.secret_multiplier, ecdsa.SECP256k1)
        print('chat_temp_sig_sk', chat_temp_sig_sk)

        height = 1
        highest_prev_hash = highest_subchain_hash

        new_timestamp = time.time()
        block_hash = hashlib.sha256((highest_prev_hash + sender + str(height+1) + tempchain_accept_data_json + str(new_timestamp)).encode('utf8'))
        signature = chat_temp_sig_sk.sign_digest(block_hash.digest())
        # print('signature', signature)

        new_tempchain_block = [block_hash.hexdigest(), highest_prev_hash, sender, height+1, tempchain_accept_data, new_timestamp, base64.b16encode(signature).decode('utf8')]
        print('new_tempchain_block', new_tempchain_block)
        rsp = requests.post('http://%s:%s/new_tempchain_block?chain=%s' % (host, port, channel_id), json = new_tempchain_block)

        store_obj.setdefault('channels', {})
        store_obj['channels'][channel_id] = base64.b16encode(chat_sk_bytes).decode('utf8')
        with open('./.messager.json', 'w') as f:
            f.write(json.dumps(store_obj))


    elif sys.argv[1] == 'block':
        host = store_obj['host']
        port = store_obj['port']
        address = sys.argv[2]

    elif sys.argv[1] == 'send':
        host = store_obj['host']
        port = store_obj['port']
        address = sys.argv[2]

if __name__ == '__main__':
    main()
