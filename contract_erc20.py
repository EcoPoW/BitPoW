
from contract_types import address, uint256
# from state import _state
# from state import _sender

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
    current_amount = _state.get('balance', 0, _to)
    new_amount = current_amount + _value
    print('before mint', current_amount)
    print('mint to', _to, _value)
    print('after mint', new_amount)
    _state.put('balance', _to, new_amount)

    current_total = _state.get('total', 0)
    new_total = current_total + _value
    print('after mint total', new_total)
    _state.put('total', new_total)


def approve(_spender:address, _value:uint256):
    pass


def allowance(_owner:address, _spender:address):
    pass


def transfer(_to:address, _value:uint256):
    print('transfer to', _to, _value)
    sender_amount = _state.get('balance', 0, _sender)
    sender_new_amount = sender_amount - _value
    assert sender_new_amount >= 0
    print('after transfer sender', sender_new_amount)
    _state.put('balance', sender_new_amount, _sender)

    to_amount = _state.get('balance', 0, _to)
    to_new_amount = to_amount + _value
    print('after transfer receiver', to_new_amount)
    _state.put('balance', to_new_amount, _to)


def transferFrom(_from:address, _to:address, _value:uint256):
    print('transferFrom')


def balanceOf(_owner:address):
    amount = _state.get('balance', 0, _owner)
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
    amount = _state.get('total', 0)
    return f'0x{amount:0>64x}'


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
