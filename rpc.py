
import json
import hashlib
import time
import math
import types

import tornado
# import requests

import web3
import eth_account
# import eth_typing
import eth_utils
import rlp
import hexbytes

import chain
import database
import tree
import vm
import state

import contract_erc20

contract_map = {
    '0x0000000000000000000000000000000000000001': contract_erc20
}

interface_map = {}
type_map = {}
for k, v in contract_erc20.__dict__.items():
    if not k.startswith('_') and type(v) in [types.FunctionType]:
        # print(k, type(v))
        # print(v.__code__.co_kwonlyargcount, v.__code__.co_posonlyargcount)
        # print(v.__code__.co_varnames[:v.__code__.co_argcount])
        # for i in v.__code__.co_varnames[:v.__code__.co_argcount]:
        #     print(v.__annotations__[i].__name__)
        params = [v.__annotations__[i].__name__ for i in v.__code__.co_varnames[:v.__code__.co_argcount]]
        func_sig = '%s(%s)' % (k, ','.join(params))
        # print(func_sig, '0x'+eth_utils.keccak(func_sig.encode('utf8')).hex()[:8])
        interface_map['0x'+eth_utils.keccak(func_sig.encode('utf8')).hex()[:8]] = v
        type_map[k] = params
print(interface_map)
print(type_map)

vm = vm.VM()
vm.import_module(contract_erc20)

V_OFFSET = 27
def eth_rlp2list(tx_rlp_bytes):
    tx_rlp_list = rlp.decode(tx_rlp_bytes)
    print(tx_rlp_list)
    nonce = int.from_bytes(tx_rlp_list[0], 'big')
    gas_price = int.from_bytes(tx_rlp_list[1], 'big')
    gas = int.from_bytes(tx_rlp_list[2], 'big')
    to = web3.Web3.to_checksum_address(tx_rlp_list[3])
    value = int.from_bytes(tx_rlp_list[4], 'big')
    data = '0x%s' % tx_rlp_list[5].hex()
    # print(tx_rlp_list[5])
    v = int.from_bytes(tx_rlp_list[6], 'big')
    r = int.from_bytes(tx_rlp_list[7], 'big')
    s = int.from_bytes(tx_rlp_list[8], 'big')
    chain_id, chain_naive_v = eth_account._utils.signing.extract_chain_id(v)
    v_standard = chain_naive_v - V_OFFSET
    return [nonce, gas_price, gas, to, value, data, chain_id], [v_standard, r, s]


def hash_of_eth_tx_list(tx_list):
    nonce = tx_list[0].to_bytes(math.ceil(tx_list[0].bit_length()/8), 'big')
    gas_price = tx_list[1].to_bytes(math.ceil(tx_list[1].bit_length()/8), 'big')
    gas = tx_list[2].to_bytes(math.ceil(tx_list[2].bit_length()/8), 'big')
    to = bytes.fromhex(tx_list[3].replace('0x', ''))
    value = tx_list[4].to_bytes(math.ceil(tx_list[4].bit_length()/8), 'big')
    data = bytes.fromhex(tx_list[5].replace('0x', ''))
    chain_id = tx_list[6].to_bytes(math.ceil(tx_list[6].bit_length()/8), 'big')
    # print([nonce, gas_price, gas, to, value, data, chain_id, 0, 0])
    rlp_bytes = rlp.encode([nonce, gas_price, gas, to, value, data, chain_id, 0, 0])
    # print('raw', rlp_bytes)
    rlp_hash = eth_utils.keccak(rlp_bytes)
    # print('hash1', rlp_hash)
    return rlp_hash

def eth_rlp2list_type2(tx_rlp_bytes):
    tx_rlp_list = rlp.decode(tx_rlp_bytes[1:])
    print(tx_rlp_list)
    nonce = int.from_bytes(tx_rlp_list[1], 'big')
    gas_price = int.from_bytes(tx_rlp_list[2], 'big')
    max_priority = int.from_bytes(tx_rlp_list[3], 'big')
    max_fee = int.from_bytes(tx_rlp_list[4], 'big')
    to = web3.Web3.to_checksum_address(tx_rlp_list[5])
    value = int.from_bytes(tx_rlp_list[6], 'big')
    data = '0x%s' % tx_rlp_list[7].hex()
    # print(tx_rlp_list[5])
    v = int.from_bytes(tx_rlp_list[9], 'big')
    r = int.from_bytes(tx_rlp_list[10], 'big')
    s = int.from_bytes(tx_rlp_list[11], 'big')
    chain_id, chain_naive_v = eth_account._utils.signing.extract_chain_id(v)
    if not chain_id:
        chain_id = 1
    v_standard = chain_naive_v - V_OFFSET
    return [nonce, gas_price, max_priority, to, value, data, chain_id], [v_standard, r, s]



# class ProxyEthRpcHandler(tornado.web.RequestHandler):
#     def options(self):
#         pass

#     def post(self):
#         print('----post----')
#         print(self.request.body)
#         rsp = requests.post('http://127.0.0.1:8545', data=self.request.body)
#         print(rsp.text)
#         self.write(rsp.text)

mpt_root = None

class EthRpcHandler(tornado.web.RequestHandler):
    def options(self):
        print('-----options-------')
        # print(self.request.arguments)
        # print(self.request.body)

        # rsp = requests.options('http://127.0.0.1:9933/')
        # print(rsp)
        # print(rsp.text)
        # self.add_header('allow', 'OPTIONS, POST')
        # self.add_header('accept', 'application/json')
        # self.add_header('vary', 'origin')
        self.add_header('access-control-allow-methods', 'OPTIONS, POST')
        self.add_header('access-control-allow-origin', '*')
        self.add_header('access-control-allow-headers', 'content-type')
        self.add_header('accept', 'application/json')
        # allow: OPTIONS, POST\r\n
        # accept: application/json\r\n
        # vary: origin\r\n
        # access-control-allow-methods: OPTIONS, POST\r\n
        # access-control-allow-origin: moz-extension://52ed146e-8386-4e74-9dae-5fe4e9ae20c8\r\n
        # access-control-allow-headers: content-type\r\n
        # content-length: 0\r\n
        # date: Thu, 24 Mar 2022 08:58:57 GMT
        # self.write('\n')

    def get(self):
        print('------get------')
        self.redirect('/dashboard')

    def post(self):
        global mpt_root
        print('------post------')
        # print(self.request.arguments)
        print(self.request.body)
        self.add_header('access-control-allow-methods', 'OPTIONS, POST')
        self.add_header('access-control-allow-origin', '*')
        req = tornado.escape.json_decode(self.request.body)
        rpc_id = req.get('id', '0')
        if req.get('method') == 'eth_blockNumber':
            highest_block_height, highest_block_hash, highest_block = chain.get_highest_block()
            resp = {'jsonrpc':'2.0', 'result': hex(highest_block_height), 'id':rpc_id}

        elif req.get('method') == 'eth_getBlockByNumber':
            highest_block_height, highest_block_hash, highest_block = chain.get_highest_block()
            # resp = {'jsonrpc':'2.0', 'result': '0x'+highest_block_hash.decode('utf8'), 'id':rpc_id}
            resp = {"jsonrpc":"2.0", "id": rpc_id,
                "result":{
                    # "number":"0x1",
                    "number": hex(highest_block_height),
                    # "hash":"0xffb0c9a9f7a192c9aaf1c1f05e32ce889ffea4006d3e016b0681b8e5b6a94ed2",
                    "hash": '0x'+highest_block_hash.decode('utf8'),
                    # "parentHash":"0x137f2bacb32744f3f8637496ec2812df9cade335762792999c1799df0157db76",
                    "nonce":"0x0000000000000042",
                    "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
                    # "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    # "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "transactionsRoot":"0x7c50a9531c6d4af23d04fd77a1d4bac9d9e1ac6c37444909a5f645ff343ffaf7",
                    "stateRoot":"0xe3fe0cf56db054e86175680de691dc8da487412edce44148d209b24586e29249",
                    # "receiptsRoot":"0x12485246f5b5efab68f826355509c375b39d179c3837e5fdd7dd7336439b5623",
                    "miner":"0xc014ba5ec014ba5ec014ba5ec014ba5ec014ba5e",
                    "difficulty":"0x20000",
                    "totalDifficulty":"0x20001",
                    "extraData":"0x",
                    "size":"0xe5f",
                    "gasLimit":"0x1c9c380",
                    "gasUsed":"0x0",
                    "baseFeePerGas":"0x0",
                    "timestamp":"0x644b949c",
                    # "transactions":["0xed65f0ac3506915ba5cc0a5da762b651816928fcc272e6f828e5f1f823f4713d"],
                    "transactions":[],
                    "uncles":[]
            }}


        elif req.get('method') == 'eth_getBalance':
            address = web3.Web3.to_checksum_address(req['params'][0])
            # block_height = req['params'][1]

            _highest_block_height, highest_block_hash, _highest_block = chain.get_highest_block()
            db = database.get_conn()
            blockstate_json = db.get(b'blockstate_%s' % highest_block_hash)
            blockstate = tornado.escape.json_decode(blockstate_json)
            # print('blockstate', blockstate)
            # print('address', address)

            msg_hash = blockstate.get('subchains', {}).get(address)
            # print('msg_hash', msg_hash, address)
            if msg_hash:
                msgstate_json = db.get(b'msgstate_%s' % msg_hash.encode('utf8'))
                msgstate = tornado.escape.json_decode(msgstate_json)
                print('msgstate', msgstate)
                balance = msgstate['balances']['SHA']
            else:
                msg_hash = b'0'*64
                balance = 1

            msg_hashes = blockstate.get('balances_to_collect', {}).get(address, [])
            for msg_hash in msg_hashes:
                print('msg_hash', msg_hash)
                msg_json = db.get(b'msg_%s' % msg_hash.encode('utf8'))
                msg = tornado.escape.json_decode(msg_json)
                print('msg', msg)
                if 'eth_raw_tx' in msg[chain.MSG_DATA]:
                    raw_tx = msg[chain.MSG_DATA]['eth_raw_tx']
                    tx, tx_from, tx_to, _tx_hash = tx_info(raw_tx)
                    if tx_to == address:
                        balance += int(tx.value/10**18)

            resp = {'jsonrpc':'2.0', 'result': hex(0*balance*(10**18)), 'id':rpc_id}

        elif req.get('method') == 'eth_getTransactionReceipt':
            msg_hash = req['params'][0]
            db = database.get_conn()
            msg_json = db.get(b'msg_%s' % msg_hash.encode('utf8')[2:])
            print(msg_json)
            msg = tornado.escape.json_decode(msg_json)
            data = msg[chain.MSG_DATA]
            # count = data[0]
            signature = msg[chain.MSG_SIGNATURE]
            eth_tx_hash = hash_of_eth_tx_list(data)
            signature_obj = eth_account.Account._keys.Signature(bytes.fromhex(signature[2:]))
            pubkey = signature_obj.recover_public_key_from_msg_hash(eth_tx_hash)
            sender = pubkey.to_checksum_address()

            result = {
                'transactionHash': msg_hash,
                'transactionIndex': 0,
                'blockHash': msg_hash,
                'blockNumber': 0,
                'from': sender,
                'to': data[3],
                'cumulativeGasUsed': 0,
                'gasUsed':0,
                'contractAddress': '',
                'logs': [],
                'logsBloom': ''
            }
            resp = {'jsonrpc':'2.0', 'result': result, 'id': rpc_id}

        elif req.get('method') == 'eth_getCode':
            resp = {'jsonrpc':'2.0', 'result': '0x0208', 'id': rpc_id}

        elif req.get('method') == 'eth_gasPrice':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_estimateGas':
            resp = {'jsonrpc':'2.0', 'result': '0x52', 'id': rpc_id}

        elif req.get('method') == 'eth_maxPriorityFeePerGas':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_getTransactionCount':
            address = web3.Web3.to_checksum_address(req['params'][0])
            db = database.get_conn()
            prev_hash = db.get(b'chain_%s' % address.encode('utf8'))
            count = 0
            if prev_hash:
                msg_json = db.get(b'msg_%s' % prev_hash)
                # print(msg_json)
                msg = tornado.escape.json_decode(msg_json)
                # print(msg)
                # count = msg[chain.MSG_HEIGHT]
                data = msg[chain.MSG_DATA]
                count = data[0]
                signature = msg[chain.MSG_SIGNATURE]
                eth_tx_hash = hash_of_eth_tx_list(data)
                signature_obj = eth_account.Account._keys.Signature(bytes.fromhex(signature[2:]))
                pubkey = signature_obj.recover_public_key_from_msg_hash(eth_tx_hash)
                sender = pubkey.to_checksum_address()
                print('sender', sender)
                print('count', count)

            resp = {'jsonrpc':'2.0', 'result': hex(count+1), 'id': rpc_id}

        elif req.get('method') == 'eth_getBlockByHash':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_sendRawTransaction':
            # 0x23a58abebeD7f43b61a285a3b33A03441bb4ED92
            # coin
            # b'{"id":2584340568916,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86e028501dcd650008252089436d8dffc83830f06d156b85b98bbe7e9d8a2290188016345785d8a000080820433a0c1b0621c7f1f8624d4b33341f6a350dc5e70b05f44b9d05ca819e0a1fdaddbf3a02b2eb0ad2be590e75f375dc960ba45af16d49f825f6e7a38a77ef22b7bba0574"]}'
            # [b'\x02', b'\x01\xdc\xd6P\x00', b'R\x08', b'6\xd8\xdf\xfc\x83\x83\x0f\x06\xd1V\xb8[\x98\xbb\xe7\xe9\xd8\xa2)\x01', b'\x01cEx]\x8a\x00\x00', b'', b'\x043', b'\xc1\xb0b\x1c\x7f\x1f\x86$\xd4\xb33A\xf6\xa3P\xdc^p\xb0_D\xb9\xd0\\\xa8\x19\xe0\xa1\xfd\xad\xdb\xf3', b'+.\xb0\xad+\xe5\x90\xe7_7]\xc9`\xbaE\xaf\x16\xd4\x9f\x82_nz8\xa7~\xf2+{\xba\x05t']

            # token
            # b'{"id":2584340568677,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf8ab018501dcd65000827b0c94000000000000000000000000000000000000000180b844a9059cbb00000000000000000000000036d8dffc83830f06d156b85b98bbe7e9d8a2290100000000000000000000000000000000000000000000000000000000000001f4820434a0f449ee1e8dd693a6ea31adfc2ad1eaa7dcd2083eb57f804096427a498d71b707a07be7206bde23bb562e6a26ec3edc1f08fc9560834ad378924df257f9f9c11d2b"]}'
            # [b'\x01', b'\x01\xdc\xd6P\x00', b'{\x0c', b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01', b'', b'\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x006\xd8\xdf\xfc\x83\x83\x0f\x06\xd1V\xb8[\x98\xbb\xe7\xe9\xd8\xa2)\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xf4', b'\x044', b'\xf4I\xee\x1e\x8d\xd6\x93\xa6\xea1\xad\xfc*\xd1\xea\xa7\xdc\xd2\x08>\xb5\x7f\x80@\x96BzI\x8dq\xb7\x07', b'{\xe7 k\xde#\xbbV.j&\xec>\xdc\x1f\x08\xfc\x95`\x83J\xd3x\x92M\xf2W\xf9\xf9\xc1\x1d+']

            # reference UNSIGNED_TRANSACTION_FIELDS for those data
            params = req.get('params', [])
            raw_tx_hex = params[0]
            # print('raw_tx_hex', raw_tx_hex)
            raw_tx_bytes = web3.Web3.to_bytes(hexstr=raw_tx_hex)
            print('raw_tx_bytes', raw_tx_bytes)
            if raw_tx_bytes.startswith(b'\x02'):
                data, vrs = eth_rlp2list_type2(raw_tx_bytes)
                tx = eth_account._utils.typed_transactions.DynamicFeeTransaction.from_bytes(hexbytes.HexBytes(raw_tx_hex))
                # tx = eth_account._utils.typed_transactions.TypedTransaction(transaction_type=2, transaction=tx)
                tx_hash = tx.hash()
                vrs = tx.vrs()
                tx_to = web3.Web3.to_checksum_address(tx.as_dict()['to'])
                tx_data = web3.Web3.to_hex(tx.as_dict()['data'])
                tx_nonce = web3.Web3.to_int(tx.as_dict()['nonce'])
            else:
                data, vrs = eth_rlp2list(raw_tx_bytes)
                tx = eth_account._utils.legacy_transactions.Transaction.from_bytes(raw_tx_bytes)
                tx_hash = eth_account._utils.signing.hash_of_signed_transaction(tx)
                vrs = eth_account._utils.legacy_transactions.vrs_from(tx)
                tx_to = web3.Web3.to_checksum_address(tx.to)
                tx_data = web3.Web3.to_hex(tx.data)
                tx_nonce = tx.nonce
            print('eth_rlp2list', data, vrs)
            # print('nonce', tx.nonce)
            tx_from = eth_account.Account._recover_hash(tx_hash, vrs=vrs)

            # contract_erc20._sender = tx_from
            vm.global_vars['_sender'] = tx_from

            # print('tx_from', tx_from)
            # print('tx.to', tx.to)
            # print('tx_to', tx_to)
            # print('txhash', tx_hash)
            # print('tx.data', tx.data)
            # contract = contract_map[tx_to.lower()]
            result = '0x'

            func_sig = tx_data[:10]
            # print(interface_map[func_sig], tx_data)
            func_params_data = tx_data[10:]
            func_params = [func_params_data[i:i+64] for i in range(0, len(func_params_data)-2, 64)]
            print('func', interface_map[func_sig].__name__, func_params)
            type_params = []
            for k, v in zip(type_map[interface_map[func_sig].__name__], func_params):
                # print('type', k, v)
                if k == 'address':
                    type_params.append(web3.Web3.to_checksum_address(web3.Web3.to_checksum_address('0x'+v[24:])))
                elif k == 'uint256':
                    type_params.append(web3.Web3.to_int(hexstr=v))

            state.load_state(mpt_root)
            print(state._mpt.root_hash())
            # result = interface_map[func_sig](*func_params)
            vm.run(type_params, interface_map[func_sig].__name__)
            print(state._mpt.root_hash())
            mpt_root = state._mpt.root_hash()

            # tx = rlp.decode(raw_tx_bytes)
            # tx, tx_from, tx_to, _tx_hash = tx_info(raw_tx_hex)

            db = database.get_conn()
            prev_hash = db.get(b'chain_%s' % tx_from.encode('utf8'))
            print('prev_hash', prev_hash)
            if prev_hash:
                msg_json = db.get(b'msg_%s' % prev_hash)
                # print('msg_json', msg_json)
                msg = tornado.escape.json_decode(msg_json)
                # print(msg)
                assert msg[chain.MSG_DATA][0] + 1 == tx_nonce
            else:
                prev_hash = b'0'*64
                assert 1 == tx_nonce

            # _msg_header, block_hash, prev_hash, sender, receiver, height, data, timestamp, signature = seq
            # data, vrs = eth_rlp2list(raw_tx_bytes)
            data_json = json.dumps(data)
            new_timestamp = time.time()
            block_hash_obj = hashlib.sha256((prev_hash.decode('utf8') + tx_from + tx_to + str(tx_nonce) + data_json + str(new_timestamp)).encode('utf8'))
            block_hash = block_hash_obj.hexdigest()
            signature_obj = eth_account.Account._keys.Signature(vrs=vrs)
            signature = signature_obj.to_hex()

            seq = ['NEW_SUBCHAIN_BLOCK', block_hash, prev_hash.decode('utf8'), 'eth', new_timestamp, data, signature]
            chain.new_subchain_block(seq)
            tree.forward(seq)

            resp = {'jsonrpc':'2.0', 'result': '0x%s' % block_hash, 'id': rpc_id}

        elif req.get('method') == 'eth_call':
            # b'{"id":58,"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000001","data":"0x01ffc9a780ac58cd00000000000000000000000000000000000000000000000000000000"},"0x6288"]}'
            # {'jsonrpc': '2.0', 'result': '0x0', 'id': 58}

            # b'{"id":"ee04ad8b-aea3-43ad-b382-948f93257db7","jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000001","data":"0x70a08231000000000000000000000000719c8d75faf8f1b117ea56205414892caab4a1b7"},"0x62c1"]}'
            params = req.get('params', [])
            state.load_state(mpt_root)
            print(state._mpt.root_hash())
            if len(params) > 0:
                if 'to' in params[0] and 'data' in params[0] and params[0]['to'].lower() in contract_map:
                    # contract = contract_map[params[0]['to'].lower()]
                    tx_data = params[0]['data']
                    result = '0x'

                    if tx_data.startswith('0x01ffc9a7'): # 80ac58cd for 721 and d9b67a26 for 1155
                        resp = {"jsonrpc":"2.0","id":rpc_id,"error":{"code":-32603,"message":"Error: Transaction reverted without a reason string","data":{"message":"Error: Transaction reverted without a reason string","data":"0x"}}}
                        resp = {"jsonrpc":"2.0","id":rpc_id,"error":-32603}
                    else:
                        func_sig = tx_data[:10]
                        print(interface_map[func_sig], tx_data)
                        func_params_data = tx_data[10:]
                        func_params = [func_params_data[i:i+64] for i in range(0, len(func_params_data)-2, 64)]
                        print('eth_call func', interface_map[func_sig].__name__, func_params)
                        # result = interface_map[func_sig](*func_params)

                        type_params = []
                        for k, v in zip(type_map[interface_map[func_sig].__name__], func_params):
                            # print('type', k, v)
                            if k == 'address':
                                type_params.append(web3.Web3.to_checksum_address(web3.Web3.to_checksum_address('0x'+v[24:])))
                            elif k == 'uint256':
                                type_params.append(web3.Web3.to_int(hexstr=v))

                        result = vm.run(type_params, interface_map[func_sig].__name__)
                        print('result', result)

                        resp = {'jsonrpc':'2.0', 'result': result or '0x', 'id': rpc_id}

                else:
                    resp = {'jsonrpc':'2.0', 'result': '0x', 'id': rpc_id}

        elif req.get('method') == 'eth_feeHistory':
            resp = {'jsonrpc':'2.0', 'result': {
                "baseFeePerGas": [
                    "0x0",
                    "0x0",
                    "0x0",
                    "0x0",
                    "0x0"
                ],
                "gasUsedRatio": [
                    0.5290747666666666,
                    0.49240453333333334,
                    0.4615576,
                    0.49407083333333335,
                    0.4669053
                ],
                "oldestBlock": "0xfab8ac",
                "reward": [
                    [
                        "0x59682f00",
                        "0x59682f00"
                    ],
                    [
                        "0x59682f00",
                        "0x59682f00"
                    ],
                    [
                        "0x3b9aca00",
                        "0x59682f00"
                    ],
                    [
                        "0x510b0870",
                        "0x59682f00"
                    ],
                    [
                        "0x3b9aca00",
                        "0x59682f00"
                    ]
                ]
            }, 'id': rpc_id}

        elif req.get('method') == 'web3_clientVersion':
            resp = {'jsonrpc':'2.0', 'result': 'BitPoW', 'id': rpc_id}

        elif req.get('method') == 'eth_chainId':
            resp = {'jsonrpc':'2.0', 'result': hex(520), 'id':rpc_id}

        elif req.get('method') == 'net_version':
            resp = {'jsonrpc':'2.0', 'result': '520','id': rpc_id}

        # print(resp)
        self.write(tornado.escape.json_encode(resp))
