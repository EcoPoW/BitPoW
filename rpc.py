

# from dataclasses import asdict, dataclass
# from pprint import pprint
# from typing import Optional
import tornado

import rlp
import web3
import eth_typing
import eth_utils
import eth_account

# from rlp.sedes import Binary, big_endian_int, binary
# from web3.auto import w3

import chain
import database

class Transaction(rlp.Serializable):
    fields = [
        ("nonce", rlp.sedes.big_endian_int),
        ("gas_price", rlp.sedes.big_endian_int),
        ("gas", rlp.sedes.big_endian_int),
        ("to", rlp.sedes.Binary.fixed_length(20, allow_empty=True)),
        ("value", rlp.sedes.big_endian_int),
        ("data", rlp.sedes.binary),
        ("v", rlp.sedes.big_endian_int),
        ("r", rlp.sedes.big_endian_int),
        ("s", rlp.sedes.big_endian_int),
    ]


# @dataclass
# class DecodedTx:
#     hash_tx: str
#     from_: str
#     to: Optional[str]
#     nonce: int
#     gas: int
#     gas_price: int
#     value: int
#     data: str
#     chain_id: int
#     r: str
#     s: str
#     v: int


# def hex_to_bytes(data: str) -> bytes:
#     return to_bytes(hexstr=HexStr(data))


def decode_raw_tx(raw_tx: str):
    raw_bytes = eth_utils.to_bytes(hexstr=eth_typing.HexStr(raw_tx))
    tx = rlp.decode(raw_bytes, Transaction)
    hash_tx = web3.Web3.toHex(eth_utils.keccak(raw_bytes))
    from_ = eth_account.Account.recover_transaction(raw_tx)
    to = web3.Web3.toChecksumAddress(tx.to) if tx.to else None
    data = web3.Web3.toHex(tx.data)
    r = hex(tx.r)
    s = hex(tx.s)
    chain_id = (tx.v - 35) // 2 if tx.v % 2 else (tx.v - 36) // 2
    print('chain_id', chain_id)
    # return DecodedTx(hash_tx, from_, to, tx.nonce, tx.gas, tx.gas_price, tx.value, data, chain_id, r, s, tx.v)


# def main():
#     raw_tx = "0xf8a910850684ee180082e48694a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb000000000000000000000000b8b59a7bc828e6074a4dd00fa422ee6b92703f9200000000000000000000000000000000000000000000000000000000010366401ba0e2a4093875682ac6a1da94cdcc0a783fe61a7273d98e1ebfe77ace9cab91a120a00f553e48f3496b7329a7c0008b3531dd29490c517ad28b0e6c1fba03b79a1dee"  # noqa
#     res = decode_raw_tx(raw_tx)
#     pprint(asdict(res))



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
            block_height = req['params'][1]

            _highest_block_height, highest_block_hash, _highest_block = chain.get_highest_block()
            db = database.get_conn()
            block_json = db.get(b'fullstate%s' % highest_block_hash)
            fullstate = tornado.escape.json_decode(block_json)
            print('fullstate', fullstate)
            balance = fullstate.get('coins', {}).get(address, 0)

            resp = {'jsonrpc':'2.0', 'result': hex(balance*(10**18)), 'id':rpc_id}
        elif req.get('method') == 'eth_getTransactionReceipt':
            pass

        elif req.get('method') == 'eth_getBlockByNumber':
            resp = {'jsonrpc':'2.0', 'result': hex(520), 'id':rpc_id}

        elif req.get('method') == 'eth_getCode':
            resp = {'jsonrpc':'2.0', 'result': '0x0208', 'id':rpc_id}

        elif req.get('method') == 'eth_gasPrice':
            resp = {'jsonrpc':'2.0', 'result': '0x0001', 'id':rpc_id}

        elif req.get('method') == 'eth_estimateGas':
            resp = {'jsonrpc':'2.0', 'result': '0x5208', 'id':rpc_id}

        elif req.get('method') == 'eth_getTransactionCount':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id':rpc_id}

        elif req.get('method') == 'eth_sendRawTransaction':
            raw_tx = req['params'][0]
            print(raw_tx)
            raw_bytes = eth_utils.to_bytes(hexstr=eth_typing.HexStr(raw_tx))
            tx = rlp.decode(raw_bytes, Transaction)
            tx_hash = web3.Web3.toHex(eth_utils.keccak(raw_bytes))
            tx_from = eth_account.Account.recover_transaction(raw_tx)
            print('from', tx_from)
            tx_to = web3.Web3.toChecksumAddress(tx.to) if tx.to else None
            print('to', tx_to)
            tx_data = web3.Web3.toHex(tx.data)
            print('data', tx_data)
            chain_id = (tx.v - 35) // 2 if tx.v % 2 else (tx.v - 36) // 2
            print('chain_id', chain_id)
            print('nonce', tx.nonce)
            print('value', tx.value)
            print('r', tx.r)
            print('s', tx.s)
            print('v', tx.v)

            resp = {'jsonrpc':'2.0', 'result': tx_hash, 'id': rpc_id}

        elif req.get('method') == 'web3_clientVersion':
            resp = {'jsonrpc':'2.0', 'result':'ByteChain', 'id':rpc_id}

        elif req.get('method') == 'net_version':
            resp = {'jsonrpc':'2.0', 'result':hex(520),'id':rpc_id}

        print(resp)
        self.write(tornado.escape.json_encode(resp))
