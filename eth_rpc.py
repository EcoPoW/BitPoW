
import json
import hashlib
import time
import types

import tornado
# import requests

import web3
import eth_account
# import eth_typing
import eth_abi
import hexbytes

import chain
import database
import tree
import vm

import contracts
import state
import eth_tx
import console
import setting


# class ProxyEthRpcHandler(tornado.web.RequestHandler):
#     def options(self):
#         pass

#     def post(self):
#         print('----post----')
#         print(self.request.body)
#         rsp = requests.post('http://127.0.0.1:8545', data=self.request.body)
#         print(rsp.text)
#         self.write(rsp.text)


class EthRpcHandler(tornado.web.RequestHandler):
    def options(self):
        self.add_header('access-control-allow-methods', 'OPTIONS, POST')
        self.add_header('access-control-allow-origin', '*')
        self.add_header('access-control-allow-headers', 'content-type')
        self.add_header('accept', 'application/json')

    def get(self):
        self.redirect('/dashboard')

    def post(self):
        # print(self.request.arguments)
        self.add_header('access-control-allow-methods', 'OPTIONS, POST')
        self.add_header('access-control-allow-origin', '*')
        req = tornado.escape.json_decode(self.request.body)
        # console.log(req)
        rpc_id = req.get('id', '0')
        if req.get('method') == 'eth_blockNumber':
            # highest_block_height, _highest_block_hash, _highest_block = chain.get_highest_block() # change to get block number
            latest_block_height = chain.get_latest_block_number()
            print(latest_block_height)
            resp = {'jsonrpc':'2.0', 'result': hex(latest_block_height), 'id':rpc_id}

        elif req.get('method') == 'eth_getBlockByNumber':
            # highest_block_height, highest_block_hash, highest_block = chain.get_highest_block()
            latest_block_height = chain.get_latest_block_number()
            latest_block_hashes = chain.get_block_hashes_by_number(latest_block_height)
            print(latest_block_height, latest_block_hashes)
            if not latest_block_hashes:
                latest_block_hashes.append('0'*64)
            # resp = {'jsonrpc':'2.0', 'result': '0x'+highest_block_hash.decode('utf8'), 'id':rpc_id}
            resp = {"jsonrpc":"2.0", "id": rpc_id,
                "result":{
                    # "number":"0x1",
                    "number": hex(latest_block_height),
                    # "hash":"0xffb0c9a9f7a192c9aaf1c1f05e32ce889ffea4006d3e016b0681b8e5b6a94ed2",
                    "hash": '0x'+latest_block_hashes[0],
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

            # _highest_block_height, highest_block_hash, _highest_block = chain.get_highest_block()
            latest_block_height = chain.get_latest_block_number()
            db = database.get_conn()
            it = db.iteritems()
            it.seek(('globalstate_%s_' % address).encode('utf8'))
            balance = 0
            for subchain_key, subchain_value in it:
                if not subchain_key.startswith(('globalstate_%s_' % address).encode('utf8')):
                    break
                print('count subchainkey', subchain_key, subchain_value)
            # blockstate_json = db.get(b'blockstate_%s' % latest_block_height)
            # blockstate = tornado.escape.json_decode(blockstate_json)
            # # print('blockstate', blockstate)
            # # print('address', address)

            # msg_hash = blockstate.get('subchains', {}).get(address)
            # # print('msg_hash', msg_hash, address)
            # if msg_hash:
            #     msgstate_json = db.get(b'msgstate_%s' % msg_hash.encode('utf8'))
            #     msgstate = tornado.escape.json_decode(msgstate_json)
            #     print('msgstate', msgstate)
            #     balance = msgstate['balances']['SHA']
            # else:
            #     msg_hash = b'0'*64
            #     balance = 1

            # msg_hashes = blockstate.get('balances_to_collect', {}).get(address, [])
            # for msg_hash in msg_hashes:
            #     print('msg_hash', msg_hash)
            #     msg_json = db.get(b'msg_%s' % msg_hash.encode('utf8'))
            #     msg = tornado.escape.json_decode(msg_json)
            #     print('msg', msg)
            #     if 'eth_raw_tx' in msg[chain.MSG_DATA]:
            #         raw_tx = msg[chain.MSG_DATA]['eth_raw_tx']
            #         tx, tx_from, tx_to, _tx_hash = tx_info(raw_tx)
            #         if tx_to == address:
            #             balance += int(tx.value/10**18)

            resp = {'jsonrpc':'2.0', 'result': hex(balance*(10**18)//10), 'id':rpc_id}

        elif req.get('method') == 'eth_getTransactionReceipt':
            msg_hash = req['params'][0]
            db = database.get_conn()
            msg_json = db.get(b'msg_%s' % msg_hash.encode('utf8')[2:])
            print(msg_json)
            msg = tornado.escape.json_decode(msg_json)
            data = msg[chain.MSG_DATA]
            # count = data[0]
            signature = msg[chain.MSG_SIGNATURE]
            eth_tx_hash = eth_tx.hash_of_eth_tx_list(data)
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
            console.log('eth_getTransactionCount address', address)
            db = database.get_conn()
            count = 0

            it = db.iteritems()
            it.seek(('subchain_%s_' % address).encode('utf8'))
            for subchain_key, subchain_value in it:
                print('count subchainkey', subchain_key, subchain_value)
                if subchain_key.decode('utf8').startswith('subchain_%s_' % address):
                    subchain_key_list = subchain_key.decode('utf8').split('_')
                    reversed_height = int(subchain_key_list[2])
                    count = setting.REVERSED_NO - reversed_height
                break

            resp = {'jsonrpc':'2.0', 'result': hex(count+1), 'id': rpc_id}

        elif req.get('method') == 'eth_getBlockByHash':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_sendRawTransaction':
            params = req.get('params', [])
            raw_tx_hex = params[0]
            # print('raw_tx_hex', raw_tx_hex)
            raw_tx_bytes = web3.Web3.to_bytes(hexstr=raw_tx_hex)
            # print('raw_tx_bytes', raw_tx_bytes)
            tx_list, vrs = eth_tx.eth_rlp2list(raw_tx_bytes)
            if len(tx_list) == 8:
                tx = eth_account._utils.typed_transactions.DynamicFeeTransaction.from_bytes(hexbytes.HexBytes(raw_tx_hex))
                # tx = eth_account._utils.typed_transactions.TypedTransaction(transaction_type=2, transaction=tx)
                tx_hash = tx.hash()
                vrs = tx.vrs()
                tx_to = web3.Web3.to_checksum_address(tx.as_dict()['to'])
                tx_data = web3.Web3.to_hex(tx.as_dict()['data'])
                tx_nonce = web3.Web3.to_int(tx.as_dict()['nonce'])
            else:
                tx = eth_account._utils.legacy_transactions.Transaction.from_bytes(raw_tx_bytes)
                tx_hash = eth_account._utils.signing.hash_of_signed_transaction(tx)
                vrs = eth_account._utils.legacy_transactions.vrs_from(tx)
                tx_to = web3.Web3.to_checksum_address(tx.to)
                tx_data = web3.Web3.to_hex(tx.data)
                tx_nonce = tx.nonce

            tx_from = eth_account.Account._recover_hash(tx_hash, vrs=vrs)
            # latest_block_height = chain.get_latest_block_number()

            # _state = state.get_state()
            # _state.block_number = latest_block_height
            # contracts.vm_map[tx_to].global_vars['_block_number'] = _state.block_number
            # contracts.vm_map[tx_to].global_vars['_call'] = state.call
            # contracts.vm_map[tx_to].global_vars['_state'] = _state
            # _state.sender = tx_from
            # contracts.vm_map[tx_to].global_vars['_sender'] = tx_from
            # _state.contract_address = tx_to
            # contracts.vm_map[tx_to].global_vars['_self'] = _state.contract_address


            # result = '0x'
            # func_sig = tx_data[:10]
            # # print(interface_map[func_sig], tx_data)
            # func_params_data = tx_data[10:]
            # func_params = [func_params_data[i:i+64] for i in range(0, len(func_params_data)-2, 64)]
            # print('func', contracts.interface_map[tx_to][func_sig].__name__, func_params)
            # func_params = []
            # for k, v in zip(contracts.params_map[tx_to][contracts.interface_map[tx_to][func_sig].__name__], func_params):
            #     # print('type', k, v)
            #     if k == 'address':
            #         func_params.append(web3.Web3.to_checksum_address('0x'+v[24:]))
            #     elif k == 'uint256':
            #         func_params.append(web3.Web3.to_int(hexstr=v))

            # # result = interface_map[func_sig](*func_params)
            # contracts.vm_map[tx_to].run(func_params, contracts.interface_map[tx_to][func_sig].__name__)

            prev_hash = '0'*64
            db = database.get_conn()
            it = db.iteritems()
            console.log(('subchain_%s_' % tx_from).encode('utf8'))
            it.seek(('subchain_%s_' % tx_from).encode('utf8'))
            for subchain_key, subchain_value in it:
                print('eth_sendRawTransaction', subchain_key, subchain_value)
                if not subchain_key.decode('utf8').startswith('subchain_%s_' % tx_from):
                    prev_hash = '0'*64
                    assert 1 == tx_nonce
                    break

                subchain_key_list = subchain_key.decode('utf8').split('_')
                reversed_height = int(subchain_key_list[2])
                count = setting.REVERSED_NO - reversed_height
                print(count, tx_nonce)
                assert count + 1 == tx_nonce

                tx = tornado.escape.json_decode(subchain_value)
                print('eth_sendRawTransaction tx', tx)
                prev_hash = tx[0]
                break

            print('eth_sendRawTransaction prev_hash', prev_hash)

            # _msg_header, block_hash, prev_hash, sender, receiver, height, data, timestamp, signature = seq
            # tx_list, vrs = eth_rlp2list(raw_tx_bytes)
            tx_list_json = json.dumps(tx_list)
            new_timestamp = time.time()
            block_hash_obj = hashlib.sha256((prev_hash + tx_from + tx_to + str(tx_nonce) + tx_list_json + str(new_timestamp)).encode('utf8'))
            block_hash = block_hash_obj.hexdigest()
            signature_obj = eth_account.Account._keys.Signature(vrs=vrs)
            signature = signature_obj.to_hex()

            seq = ['NEW_SUBCHAIN_BLOCK', block_hash, prev_hash, 'eth', new_timestamp, tx_list, signature]
            chain.new_subchain_block(seq)
            tree.forward(seq)

            resp = {'jsonrpc':'2.0', 'result': '0x%s' % block_hash, 'id': rpc_id}

        elif req.get('method') == 'eth_call':
            console.log(req)
            params = req.get('params', [])
            print(params)
            #try:
            #if len(params) > 0:
                #if 'to' in params[0] and 'data' in params[0] and params[0]['to'].lower() in contracts.contract_map:
                    # contract = contract_map[params[0]['to'].lower()]
            tx_to = params[0]['to']
            tx_data = params[0]['data']
            #if tx_data.startswith('0x01ffc9a7'): # 80ac58cd for 721 and d9b67a26 for 1155
                #resp = {"jsonrpc":"2.0","id":rpc_id,"error":{"code":-32603,"message":"Error: Transaction reverted without a reason string","data":{"message":"Error: Transaction reverted without a reason string","data":"0x"}}}
            #    resp = {"jsonrpc":"2.0","id":rpc_id,"error":-32603}

            if tx_to in contracts.vm_map:
                latest_block_height = chain.get_latest_block_number()

                _state = state.get_state()
                _state.block_number = latest_block_height
                contracts.vm_map[tx_to].global_vars['_block_number'] = _state.block_number
                contracts.vm_map[tx_to].global_vars['_call'] = state.call
                contracts.vm_map[tx_to].global_vars['_state'] = _state
                # contracts.vm_map[tx_to].global_vars['_sender'] = tx_from
                _state.contract_address = tx_to
                contracts.vm_map[tx_to].global_vars['_self'] = _state.contract_address

                func_sig = tx_data[:10]
                # print(contracts.interface_map[tx_to][func_sig], tx_data)
                func_params_data = tx_data[10:]
                # result = interface_map[func_sig](*func_params)

                func_params_type = contracts.params_map[tx_to][contracts.interface_map[tx_to][func_sig].__name__]
                # console.log(func_params_type)
                # console.log(func_params_data)
                func_params = eth_abi.decode(func_params_type, hexbytes.HexBytes(func_params_data))
                # console.log(func_params)

                value = contracts.vm_map[tx_to].run(func_params, contracts.interface_map[tx_to][func_sig].__name__)
                func_return_type = contracts.return_map[tx_to][contracts.interface_map[tx_to][func_sig].__name__]
                console.log(func_return_type, value)
                result = eth_abi.encode([func_return_type], [value])
                print('result', result)

                resp = {'jsonrpc':'2.0', 'result': '0x'+result.hex(), 'id': rpc_id}

            #except:
            #    resp = {'jsonrpc':'2.0', 'result': '0x', 'id': rpc_id}

            else:
                #resp = {"jsonrpc":"2.0","id":rpc_id,"error":{"code":-32603,"message":"Error: Transaction reverted without a reason string","data":{"message":"Error: Transaction reverted without a reason string","data":"0x"}}}
                resp = {"jsonrpc":"2.0","id":rpc_id,"error":-32603}
                #resp = {'jsonrpc':'2.0', 'result': '0x0000000000000000000000000000000000000000000000000000000000000000', 'id': rpc_id}
            print('resp', resp)

        elif req.get('method') == 'eth_feeHistory':
            resp = {'jsonrpc':'2.0', 'result': {}, 'id': rpc_id}
        #     # db = database.get_conn()
        #     # it = db.iteritems()
        #     # it.seek(('headerblock_').encode('utf8'))
        #     # no = 0
        #     # for k, v in it:
        #     #     print('eth_feeHistory', k, v)
        #     #     if k.decode('utf8').startswith('headerblock_'):
        #     #         ks = k.decode('utf8').split('_')
        #     #         reverse_no = int(ks[1])
        #     #         no = setting.REVERSED_NO - reverse_no
        #     #         oldest = ks[2]
        #     #     break

        #     resp = {'jsonrpc':'2.0', 'result': {
        #         "baseFeePerGas": [
        #             "0x0",
        #             "0x0",
        #             "0x0",
        #             "0x0",
        #             "0x0"
        #         ],
        #         "gasUsedRatio": [
        #             0.5290747666666666,
        #             0.49240453333333334,
        #             0.4615576,
        #             0.49407083333333335,
        #             0.4669053
        #         ],
        #         "oldestBlock": "0xfab8ac",
        #         "reward": [
        #             [
        #                 "0x59682f00",
        #                 "0x59682f00"
        #             ],
        #             [
        #                 "0x59682f00",
        #                 "0x59682f00"
        #             ],
        #             [
        #                 "0x3b9aca00",
        #                 "0x59682f00"
        #             ],
        #             [
        #                 "0x510b0870",
        #                 "0x59682f00"
        #             ],
        #             [
        #                 "0x3b9aca00",
        #                 "0x59682f00"
        #             ]
        #         ]
        #     }, 'id': rpc_id}

        elif req.get('method') == 'web3_clientVersion':
            resp = {'jsonrpc':'2.0', 'result': 'BitPoW', 'id': rpc_id}

        elif req.get('method') == 'eth_chainId':
            resp = {'jsonrpc':'2.0', 'result': hex(520), 'id':rpc_id}

        elif req.get('method') == 'net_version':
            resp = {'jsonrpc':'2.0', 'result': '520','id': rpc_id}

        # print(resp)
        self.write(tornado.escape.json_encode(resp))


