
import web3

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



_balance = {
    '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266': 100000
}
# hardhat test Account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80


def init(_name, _symbol, _decimals):
    # global name
    # global symbol
    # global decimals

    # if not (name, symbol, decimals):
    #     name = _name
    #     symbol = _symbol
    #     decimals = _decimals
    pass


def mint(_amount, _to):
    pass


def transfer(_amount, _to):
    pass


def transferFrom():
    pass


def balanceOf(user):
    user_bytes = web3.Web3.toBytes(hexstr=user)
    user_addr = web3.Web3.toChecksumAddress(user_bytes[12:])
    amount = _balance.get(user_addr)
    return web3.Web3.toHex(amount)
    # return '0x0000000000000000000000000000000000000000000000000000000000001000'


def approve():
    pass


def allowance():
    pass


def name():
    return None

def symbol():
    return '0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003504f570000000000000000000000000000000000'

def decimals():
    return '0x0000000000000000000000000000000000000000000000000000000000000000'

def totalSupply():
    return 0


import eth_utils

interface_map = {
    '0x'+eth_utils.keccak(b'transfer(address,uint256)').hex()[:8]: transfer,
    '0x'+eth_utils.keccak(b'balanceOf(address)').hex()[:8]: balanceOf,
    '0x'+eth_utils.keccak(b'decimals()').hex()[:8]: decimals,
    '0x'+eth_utils.keccak(b'allowance(address,address)').hex()[:8]: allowance,
    '0x'+eth_utils.keccak(b'symbol()').hex()[:8]: symbol,
    '0x'+eth_utils.keccak(b'totalSupply()').hex()[:8]: totalSupply,
    '0x'+eth_utils.keccak(b'name()').hex()[:8]: name,
    '0x'+eth_utils.keccak(b'approve(address,uint256)').hex()[:8] : approve,
    '0x'+eth_utils.keccak(b'transferFrom(address,address,uint256)').hex()[:8] : transferFrom,
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
