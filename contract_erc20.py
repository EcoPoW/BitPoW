
from contract_types import address, string, uint8, uint256, bytes4

# _state
# _self, _sender, _caller, _call
# print

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


def init(_name:string, _symbol:string, _decimals:uint8, _owner:address) -> None:
    name = _state.get('name', None, _self)
    if not name:
        _state.put('name', _name, _self)

    symbol = _state.get('symbol', None, _self)
    if not symbol:
        _state.put('symbol', _symbol, _self)

    decimals = _state.get('decimals', None, _self)
    if not decimals:
        _state.put('decimals', _decimals, _self)

    owner = _state.get('owner', None, _self)
    if not owner:
        _state.put('owner', _owner, _self)


def mint(_to:address, _value:uint256) -> bool:
    owner = _state.get('owner', None, _self)
    if owner and owner != _sender:
        return False

    current_amount = _state.get('balance', 0, _to)
    new_amount = current_amount + _value
    print('before mint', current_amount)
    print('mint to', _to, _value)
    print('after mint', new_amount)
    _state.put('balance', new_amount, _to)

    current_total = _state.get('total', 0, _self)
    new_total = current_total + _value
    print('after mint total', new_total)
    _state.put('total', new_total, _self)

    return True

def approve(_spender:address, _value:uint256) -> bool:
    allowance = _state.get('allowance', {}, _sender)
    allowance[_spender] = _value
    print(allowance)
    _state.put('allowance', allowance, _sender)
    return True

def allowance(_owner:address, _spender:address) -> uint256:
    allowance = _state.get('allowance', {}, _owner)
    print('allowance', allowance)
    value = allowance.get(_spender, 0)
    # return value
    return f'0x{value:0>64x}'

def transfer(_to:address, _value:uint256) -> bool:
    print('transfer to', _to, _value)
    sender_amount = _state.get('balance', 0, _sender)
    sender_new_amount = sender_amount - _value
    print('sender_amount', sender_amount, _value)
    print('sender_new_amount', sender_new_amount)
    assert sender_new_amount >= 0
    print('after transfer sender', sender_new_amount)
    _state.put('balance', sender_new_amount, _sender)

    receiver_amount = _state.get('balance', 0, _to)
    receiver_new_amount = receiver_amount + _value
    print('after transfer receiver', receiver_new_amount)
    _state.put('balance', receiver_new_amount, _to)


def transferFrom(_from:address, _to:address, _value:uint256) -> bool:
    print('erc20 transferFrom', _from, _to, _self)

    allowance = _state.get('allowance', {}, _from)
    print('allowance', allowance)
    value = allowance.get(_to, 0)
    print('value', value)
    assert value >= _value
    allowance[_to] = value - _value
    _state.put('allowance', allowance, _from)

    sender_amount = _state.get('balance', 0, _from)
    sender_new_amount = sender_amount - _value
    print('sender_amount', sender_amount, _value)
    print('sender_new_amount', sender_new_amount)
    assert sender_new_amount >= 0
    print('after transfer sender', sender_new_amount)
    _state.put('balance', sender_new_amount, _from)

    receiver_amount = _state.get('balance', 0, _to)
    receiver_new_amount = receiver_amount + _value
    print('after transfer receiver', receiver_new_amount)
    _state.put('balance', receiver_new_amount, _to)


def balanceOf(_owner:address) -> uint256:
    amount = _state.get('balance', 0, _owner)
    print('balanceOf', _owner, amount)
    return amount
    # return f'0x{amount:0>64x}'
    # return '0x0000000000000000000000000000000000000000000000000000000000001000'


def name() -> string:
    name = _state.get('name', '', _self)
    print('name', name)
    return name

def symbol() -> string:
    sym = _state.get('symbol', '', _self)
    print('symbol', sym)
    return sym
    # sym = hex(ord('U'))[2:]
    # print('sym', sym)
    # return '0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001%s00000000000000000000000000000000000000' % sym
    # return '0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003504f570000000000000000000000000000000000' #POW

def decimals() -> uint8:
    dec = _state.get('decimals', 0, _self)
    print('decimals', dec)
    return dec
    #return f'0x{18:0>64x}'

def totalSupply() -> uint256:
    amount = _state.get('total', 0, _self)
    return amount
    # return f'0x{amount:0>64x}'

def supportsInterface(_bytes:bytes4) -> bool:
    print('bytes4', _bytes.hex())
    if _bytes.hex() == '80ac58cd': # 721
        return False
    if _bytes.hex() == 'd9b67a26': # 1155
        return False
    return True

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
