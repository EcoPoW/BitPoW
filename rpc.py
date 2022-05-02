
import json
import hashlib
import time

import tornado

import web3
import eth_account
import eth_typing
import eth_utils

import chain
import database
import tree

def tx_info(raw_tx):
    tx_from = eth_account.Account.recover_transaction(raw_tx)
    raw_bytes = eth_utils.to_bytes(hexstr=eth_typing.HexStr(raw_tx))
    tx = eth_account._utils.legacy_transactions.Transaction.from_bytes(raw_bytes)
    tx_hash = web3.Web3.toHex(eth_utils.keccak(raw_bytes))
    print('from', tx_from)
    tx_to = web3.Web3.toChecksumAddress(tx.to) if tx.to else None
    print('to', tx_to)
    tx_data = web3.Web3.toHex(tx.data)
    print('data', tx_data)
    chain_id, _ = eth_account._utils.signing.extract_chain_id(tx.v)
    print('chain_id', chain_id)
    print('nonce', tx.nonce)
    print('value', tx.value)
    print('gas', tx.gas)
    print('gasPrice', tx.gasPrice)
    print('r', tx.r)
    print('s', tx.s)
    print('v', tx.v)
    tx.tx_from = tx_from
    return tx, tx_from, tx_from, tx.nonce, tx_hash

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
        self.add_header('access-control-allow-origin', 'moz-extension://52ed146e-8386-4e74-9dae-5fe4e9ae20c8')
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

    def post(self):
        print('------post------')
        print(self.request.arguments)
        print(self.request.body)
        self.add_header('access-control-allow-methods', 'OPTIONS, POST')
        self.add_header('access-control-allow-origin', 'moz-extension://52ed146e-8386-4e74-9dae-5fe4e9ae20c8')
        req = tornado.escape.json_decode(self.request.body)
        rpc_id = req['id']
        if req.get('method') == 'eth_chainId':
            resp = {'jsonrpc':'2.0', 'result': hex(520), 'id':rpc_id}
        elif req.get('method') == 'eth_blockNumber':
            resp = {'jsonrpc':'2.0', 'result': hex(10), 'id':rpc_id}
        elif req.get('method') == 'eth_getBalance':
            address = web3.Web3.toChecksumAddress(req['params'][0])
            # block_height = req['params'][1]

            _highest_block_height, highest_block_hash, _highest_block = chain.get_highest_block()
            db = database.get_conn()
            block_json = db.get(b'fullstate%s' % highest_block_hash)
            fullstate = tornado.escape.json_decode(block_json)
            print('fullstate', fullstate)
            print('address', address)
            balance = fullstate.get('tokens', {}).get('SHARES', {}).get(address, 0)

            resp = {'jsonrpc':'2.0', 'result': hex(balance*(10**18)), 'id':rpc_id}
        elif req.get('method') == 'eth_getTransactionReceipt':
            resp = {'jsonrpc':'2.0', 'result': {}, 'id':rpc_id}

        elif req.get('method') == 'eth_getBlockByNumber':
            resp = {'jsonrpc':'2.0', 'result': hex(520), 'id':rpc_id}

        elif req.get('method') == 'eth_getCode':
            resp = {'jsonrpc':'2.0', 'result': '0x0208', 'id':rpc_id}

        elif req.get('method') == 'eth_gasPrice':
            resp = {'jsonrpc':'2.0', 'result': '0x00', 'id':rpc_id}

        elif req.get('method') == 'eth_estimateGas':
            resp = {'jsonrpc':'2.0', 'result': '0x5208', 'id':rpc_id}

        elif req.get('method') == 'eth_getTransactionCount':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id':rpc_id}

        elif req.get('method') == 'eth_sendRawTransaction':
            raw_tx = req['params'][0]
            print('raw_tx', raw_tx)
            tx, tx_from, tx_to, tx_nonce, tx_hash = tx_info(raw_tx)
            db = database.get_conn()
            prev_hash = db.get(b'chain%s' % tx_from[2:].encode('utf8')) or '0'*64
            assert prev_hash

            new_timestamp = time.time()
            # _msg_header, block_hash, prev_hash, sender, receiver, height, data, timestamp, signature = seq
            data = {'eth_raw_tx': raw_tx}
            data_json = json.dumps(data)
            block_hash_obj = hashlib.sha256((prev_hash + tx_from + tx_to + str(tx_nonce+1) + data_json + str(new_timestamp)).encode('utf8'))
            block_hash = block_hash_obj.hexdigest()
            signature = 'eth'
            chain.new_subchain_block(['NEW_SUBCHAIN_BLOCK', block_hash, prev_hash, tx_from, tx_to, tx_nonce+1, data, new_timestamp, signature])

            tree.forward(['NEW_SUBCHAIN_BLOCK', tx_from, tx_to, tx_nonce])

            resp = {'jsonrpc':'2.0', 'result': tx_hash, 'id': rpc_id}

        elif req.get('method') == 'web3_clientVersion':
            resp = {'jsonrpc':'2.0', 'result':'ByteChain', 'id':rpc_id}

        elif req.get('method') == 'net_version':
            resp = {'jsonrpc':'2.0', 'result': hex(520),'id':rpc_id}

        print(resp)
        self.write(tornado.escape.json_encode(resp))
