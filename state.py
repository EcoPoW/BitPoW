
import tornado.escape

import database


class address(str):pass
class uint256(int):pass

CONTRACT_ADDRESS = b'0x0000000000000000000000000000000000000001'

contract_address = CONTRACT_ADDRESS


db = database.get_conn()
_mpt = None

def load_state(root):
    global _mpt
    _mpt = database.get_mpt(root)
    print('root', _mpt.root())
    print('root hash', _mpt.root_hash())

# _mpt.update(b'%s_balance_0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' % contract_address, tornado.escape.json_encode(10**20))
# _mpt.update(b'%s_total' % contract_address, tornado.escape.json_encode(10**20))


class State:
    # def __setitem__(self, key, value):
    def put(self, key, value):
        global _mpt
        value_json = tornado.escape.json_encode(value)
        _mpt.update(b'%s_%s' % (contract_address, key.encode('utf8')), value_json)


    # def __getitem__(self, key):
    def get(self, key, default):
        global _mpt
        print('_mpt', _mpt)
        try:
            value_json = _mpt.get(b'%s_%s' % (contract_address, key.encode('utf8')))
            value = tornado.escape.json_decode(value_json)
        except:
            value = default

        return value

_state = State()
_sender = None
