

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


name = None
symbol = None
decimals = None
totalSupply = 0

balance = {}

def init(_name, _symbol, _decimals):
    global name
    global symbol
    global decimals

    if not (name, symbol, decimals):
        name = _name
        symbol = _symbol
        decimals = _decimals


def mint(_amount, _to):
    pass


def transfer(_amount, _to):
    pass


def transferFrom():
    pass


def balanceOf(user):
    pass


def approve():
    pass


def allowance():
    pass


import eth_utils

interface_map = {
    '0x'+eth_utils.keccak(b'transfer(address,uint256)').hex()[:10]: transfer,
    '0x'+eth_utils.keccak(b'balanceOf(address)').hex()[:10]: balanceOf,
    '0x'+eth_utils.keccak(b'decimals()').hex()[:10]: decimals,
    '0x'+eth_utils.keccak(b'allowance(address,address)').hex()[:10]: allowance,
    '0x'+eth_utils.keccak(b'symbol()').hex()[:10]: symbol,
    '0x'+eth_utils.keccak(b'totalSupply()').hex()[:10]: totalSupply,
    '0x'+eth_utils.keccak(b'name()').hex()[:10]: name,
    '0x'+eth_utils.keccak(b'approve(address,uint256)').hex()[:10] : approve,
    '0x'+eth_utils.keccak(b'transferFrom(address,address,uint256)').hex()[:10] : transferFrom,
}

# transfer(address,uint256)： 0xa9059cbb
# balanceOf(address)：0x70a08231
# decimals()：0x313ce567
# allowance(address,address)： 0xdd62ed3e
# symbol()：0x95d89b41
# totalSupply()：0x18160ddd
# name()：0x06fdde03
# approve(address,uint256)：0x095ea7b3
# transferFrom(address,address,uint256)： 0x23b872dd
