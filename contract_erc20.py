

import tornado.escape

import database

class address(str):pass
class uint256(int):pass

class MPT:
    # def __setitem__(self, key, value):
    def put(self, key, value):
        global _mpt
        _mpt.put(key, value)


    # def __getitem__(self, key):
    def get(self, key, default):
        global _mpt
        try:
            current_json = _mpt.get(b'%s_%s' % (CONTRACT_ADDRESS, key.encode('utf8')))
            current_value = tornado.escape.json_decode(current_json)
        except:
            current_value = default

        return current_value


# function name() public view returns (string)
# function symbol() public view returns (string)
# function decimals() public view returns (uint8)
# function totalSupply() public view returns (uint256)
# function balanceOf(address _owner) public view returns (uint256 balance)
# function transfer(address _to, uint256 _value) public returns (bool success)
# function transferFrom(address _from, address _to, uint256 _value) public returns (bool success)
# function approve(address _spender, uint256 _value) public returns (bool success)
# function allowance(address _owner, address _spender) public view returns (uint256 remaining)

# event Transfer(address indexed _from, address indexed _to, uint256 _value)
# event Approval(address indexed _owner, address indexed _spender, uint256 _value)

CONTRACT_ADDRESS = b'0x0000000000000000000000000000000000000001'

_sender = None

# def init(_name, _symbol, _decimals):
#     global name
#     global symbol
#     global decimals

#     if not (name, symbol, decimals):
#         name = _name
#         symbol = _symbol
#         decimals = _decimals
#     pass


def mint(_to:address, _value:uint256):
    current_amount = mpt.get('balance_%s' % _to, 0)
    new_amount = current_amount + _value
    print('before mint', current_amount)
    print('mint to', _to, _value)
    print('after mint', new_amount)
    new_amount_json = tornado.escape.json_encode(new_amount)
    _mpt.update(b'%s_balance_%s' % (CONTRACT_ADDRESS, _to.encode('utf8')), new_amount_json.encode('utf8'))

    current_total_json = _mpt.get(b'%s_total' % CONTRACT_ADDRESS)
    current_total = tornado.escape.json_decode(current_total_json)
    new_total = current_total + _value
    print('after mint total', new_total)
    new_total_json = tornado.escape.json_encode(new_total)
    _mpt.update(b'%s_total' % CONTRACT_ADDRESS, new_total_json.encode('utf8'))


def approve(_spender:address, _value:uint256):
    pass


def allowance(_owner:address, _spender:address):
    pass


def transfer(_to:address, _value:uint256):
    print('transfer to', _to, _value)
    sender_amount = mpt.get('balance_%s' % _sender, 0)
    sender_new_amount = sender_amount - _value
    assert sender_new_amount >= 0
    print('after transfer sender', sender_new_amount)
    sender_new_amount_json = tornado.escape.json_encode(sender_new_amount)
    _mpt.update(b'%s_balance_%s' % (CONTRACT_ADDRESS, _sender.encode('utf8')), sender_new_amount_json.encode('utf8'))

    current_amount = mpt.get('balance_%s' % _sender, 0)
    new_amount = current_amount + _value
    print('after transfer receiver', new_amount)
    new_amount_json = tornado.escape.json_encode(new_amount)
    _mpt.update(b'%s_balance_%s' % (CONTRACT_ADDRESS, _to.encode('utf8')), new_amount_json.encode('utf8'))


def transferFrom(_from:address, _to:address, _value:uint256):
    print('transferFrom')


def balanceOf(_owner:address):
    amount = mpt.get('balance_%s' % _owner, 0)
    print('balanceOf', _owner, amount)

    return f'0x{amount:0>64x}'
    # return '0x0000000000000000000000000000000000000000000000000000000000001000'


def name():
    return None

def symbol():
    sym = hex(ord('U'))[2:]
    print('sym', sym)
    return '0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001%s00000000000000000000000000000000000000' % sym
    # return '0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003504f570000000000000000000000000000000000' #POW

def decimals():
    return f'0x{18:0>64x}'

def totalSupply():
    amount = mpt.get('total', 0)
    return f'0x{amount:0>64x}'


database.get_conn()
_mpt = database.get_mpt()
_mpt.update(b'%s_balance_0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' % CONTRACT_ADDRESS, tornado.escape.json_encode(10**20))
_mpt.update(b'%s_total' % CONTRACT_ADDRESS, tornado.escape.json_encode(10**20))
print('root', _mpt.root())
print('root hash', _mpt.root_hash())

mpt = MPT()

# hardhat test Account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80


if __name__ == '__main__':
    for i in range(2):
        mint('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 1000)
    _sender = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
    transfer('0x0000000000000000000000000000000000000002', 1000)
    balanceOf('0x0000000000000000000000000000000000000002')
    print(totalSupply())
    print(symbol())
    print(decimals())

    # t0 = time.time()
    # for i in range(10000):
    #     balanceOf('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')
    # print(time.time() - t0)
