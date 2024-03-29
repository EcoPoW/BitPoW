# from typing import List
from contract_types import address, string, uint256, bytes4, bytes32

def init(_owner: address) -> None: # _name: string, _symbol: string, _baseTokenURI: string
    # name = _get('name')
    # if not name:
    #     _put(_self, 'name', _name)

    # symbol = _get('symbol')
    # if not symbol:
    #     _put(_self, 'symbol', _symbol)

    owner = _get('owner')
    if not owner:
        _put(_self, 'owner', _owner)

    #baseTokenURI = _get('baseTokenURI')
    #if not baseTokenURI:
    #    _put(_self, 'baseTokenURI', _baseTokenURI)

def mint(_to: address, _token_id: uint256) -> bool:
    owner = _get('owner')
    print('mint sender owner', _sender, owner)
    if owner != '0x0000000000000000000000000000000000000000' and owner != _sender:
        return False
    
    current_owner = _get('owners', None, str(_token_id))
    if current_owner:
        return False
    current_addr = _get('addrs', None, _to)
    if current_addr:
        return False

    _put(_to, 'owners', _to, str(_token_id))
    _put(_to, 'addrs', str(_token_id), _to)

    #current_amount = _get('balance', 0, _to)
    #new_amount = current_amount + 1
    #_put(_to, 'balance', new_amount, _to)

    return True

def transferFrom(_from: address, _to: address, _token_id: uint256) -> bool:
    print('transferFrom', _sender, _from, _to, _token_id)
    current_owner = ownerOf(_token_id)
    assert current_owner == _from
    print('current_owner', current_owner)
    approved_address = getApproved(_token_id)
    print('approved_address', approved_address)
    assert approved_address == _sender
    _put('owners', _to, _token_id)
    old_balance = _get('balance', 0, _from)
    _put('balance', old_balance - 1, _from)

    new_balance = _get('balance', 0, _to)
    _put('balance', new_balance + 1, _to)
    return True

def transfer(_to: address, _token_id: uint256) -> bool:
    print('transfer to', _sender, _to, _token_id)
    token_owner = ownerOf(_token_id)
    assert token_owner == _sender
    print('token owner', token_owner)
    _put('owners', _to, _token_id)
    old_balance = _get('balance', 0, _sender)
    _put('balance', old_balance - 1, _sender)

    new_balance = _get('balance', 0, _to)
    _put('balance', new_balance + 1, _to)
    return True


def approve(_approved: address, _token_id: uint256):
    current_owner = ownerOf(_token_id)
    assert  current_owner != _sender 
    _put('tokenApprovals', _approved, _token_id)
    
def getApproved(_token_id: uint256) -> address:
    current_approved = _put('tokenApprovals', None, _token_id)
    if current_approved is None:
         return '0x0000000000000000000000000000000000000000'
    return current_approved

# def setApprovalForAll(_operator: address, _approved: bool) -> None:
#     current_owner = ownerOf(_token_id)
#     assert  current_owner != _sender 
#     operatorApprovals = _get('operatorApprovals', {}, _self)
#     operatorApprovals.put(_operator, _approved)

# def isApprovedForAll(_owner: address, _operator: address) -> bool:
#     operatorApprovals = _get('operatorApprovals', {}, _owner)
#     operatorApprovals.get(_operator, False)

def name() -> string:
    name = _get('name', '')
    print('name', name)
    return name

def symbol() -> string:
    sym = _get('symbol', '')
    print('symbol', sym)
    return sym

#def tokenURI(_token_id: uint256) -> string:
#    baseURI = _get('baseTokenURI', '')
#    URI = baseURI + _token_id
#    print('baseURI', URI)
#    return URI

def supportsInterface(_interfaceId: bytes4) -> bool:
    print('bytes4', _interfaceId.hex())
    if _interfaceId.hex() == '80ac58cd': # 721
        return True
    return False

def balanceOf(_owner: address) -> uint256:
    balance = _get('balance', 0, _owner)
    return balance

def ownerOf(_token_id: uint256) -> address:
    current_owner = _get('owners', None, _token_id)
    if current_owner is None:
        return '0x0000000000000000000000000000000000000000'
    return current_owner

def tokenId(_owner: address) -> uint256:
    current_owner = _get('owners', None, _owner)
    if current_owner is None:
        return '0x0000000000000000000000000000000000000000'
    return current_owner

# def setWhitelist(_root: string):
#     owner = _get('owner')
#     print('mint sender owner', _sender, owner)
#     if owner != '0x0000000000000000000000000000000000000000' and owner != _sender:
#         return False

# def regWhitelist(_proof: List[bytes32], _name: string): # 3.8
# def regWhitelist(_proof: list[bytes32], _name: string): # 3.10
#     print('proof', _proof, 'name', _name)

def setSigner(_signer: string):
    owner = _get('owner')

def regWithSigner(_handle: string, _proof: string): # 3.10
    _SYMBOLS = "abcdefghijklmnopqrstuvwxyz0123456789_"
    print('handle', _handle, 'proof', _proof)
    token_id = 0
    for i in range(len(_handle)):
        j = _SYMBOLS.index(_handle[i])
        token_id += len(_SYMBOLS)**i * (j+1)
        print('token_id', token_id)
    print('token_id all', token_id)
    print('mint', mint)
    mint(_sender, token_id)

def setOwner(_owner: string):
    owner = _get('owner')

def setSuspend(_suspend: bool):
    owner = _get('owner')

def erc20_transfer(_suspend: bool):
    owner = _get('owner')
    _call('0x0000000000000000000000000000000000000005', 'transferFrom', [_sender, _self, _value])

#def resolve(_id: string) -> address:
#    pass

#def lookup(_addr: address) -> string:
#    pass

