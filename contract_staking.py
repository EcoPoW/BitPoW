
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


def stake(_value:uint256):
    contract = _state.call('0x0000000000000000000000000000000000000001')
    print(_sender, _self, _value)
    contract.transferFrom(_sender, _self, _value)

def unstake(_spender:address, _value:uint256):
    pass


