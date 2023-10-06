from contract_types import address, string, uint256, bytes4

def init(_name: string, _symbol: string, _owner: address, _baseTokenURI: string) -> None:
    name = _get('name')
    if not name:
        _put(_self, 'name', _name)

    symbol = _get('symbol')
    if not symbol:
        _put(_self, 'symbol', _symbol)

    owner = _get('owner')
    if not owner:
        _put(_self, 'owner', _owner)

    baseTokenURI = _get('baseTokenURI')
    if not baseTokenURI:
        _put(_self, 'baseTokenURI', _baseTokenURI)

def mint(_to: address, _tokenId: uint256) -> bool:
    owner = _get('owner')
    print('mint sender owner', _sender, owner)
    if owner != '0x0000000000000000000000000000000000000000' and owner != _sender:
        return False
    
    current_owner = _get('owners', None, str(_tokenId))
    if current_owner:
        return False
    _put(_to, 'owners', _to, str(_tokenId))

    current_amount = _get('balance', 0, _to)
    new_amount = current_amount + 1
    _put(_to, 'balance', new_amount, _to)

    return True

def ownerOf(_tokenId: uint256) -> address:
    current_owner = _get('owners', None, _tokenId)
    if current_owner is None:
        return '0x0000000000000000000000000000000000000000'
    return current_owner

def transferFrom(_from: address, _to: address, _tokenId: uint256) -> bool:
    print('transferFrom', _sender, _from, _to, _tokenId)
    current_owner = ownerOf(_tokenId)
    assert current_owner == _from
    print('current_owner', current_owner)
    approved_address = getApproved(_tokenId)
    print('approved_address', approved_address)
    assert approved_address == _sender
    _put('owners', _to, _tokenId)
    old_balance = _get('balance', 0, _from)
    _put('balance', old_balance - 1, _from)

    new_balance = _get('balance', 0, _to)
    _put('balance', new_balance + 1, _to)
    return True

def transfer(_to:address, _tokenId:uint256) -> bool:
    print('transfer to', _sender, _to, _tokenId)
    token_owner = ownerOf(_tokenId)
    assert token_owner == _sender
    print('token owner', token_owner)
    _put('owners', _to, _tokenId)
    old_balance = _get('balance', 0, _sender)
    _put('balance', old_balance - 1, _sender)

    new_balance = _get('balance', 0, _to)
    _put('balance', new_balance + 1, _to)
    return True


def approve(_approved: address, _tokenId: uint256):
    current_owner = ownerOf(_tokenId)
    assert  current_owner != _sender 
    _put('tokenApprovals', _approved, _tokenId)
    
def getApproved(_tokenId: uint256) -> address:
    current_approved = _put('tokenApprovals', None, _tokenId)
    if current_approved is None:
         return '0x0000000000000000000000000000000000000000'
    return current_approved

def setApprovalForAll(_operator: address, _approved: bool) -> None:
    current_owner = ownerOf(_tokenId)
    assert  current_owner != _sender 
    operatorApprovals = _get('operatorApprovals', {}, _self)
    operatorApprovals.put(_operator, _approved)

def isApprovedForAll(_owner: address, _operator: address) -> bool:
    operatorApprovals = _get('operatorApprovals', {}, _owner)
    operatorApprovals.get(_operator, False)

def balanceOf(_owner: address) -> uint256:
    balance = _get('balance', 0, _owner)
    return balance

def name() -> string:
    name = _get('name', '')
    print('name', name)
    return name

def symbol() -> string:
    sym = _get('symbol', '')
    print('symbol', sym)
    return sym

def tokenURI(_tokenId: uint256) -> string:
    baseURI = _get('baseTokenURI', '')
    URI = baseURI + _tokenId
    print('baseURI', URI)
    return URI


def supportsInterface(_interfaceId: bytes4) -> bool:
    print('bytes4', _interfaceId.hex())
    if _interfaceId.hex() == '80ac58cd': # 721
        return True
    return False

