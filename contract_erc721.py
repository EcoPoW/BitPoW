from contract_types import address, string, uint256, bytes4

def init(_name: string, _symbol: string, _owner: address, _baseTokenURI: string) -> None:
    name = _get('name', None, _self)
    if not name:
        _put('name', _name, _self)

    symbol = _get('symbol', None, _self)
    if not symbol:
        _put('symbol', _symbol, _self)

    owner = _get('owner', None, _self)
    if not owner:
        _put('owner', _owner, _self)

    baseTokenURI = _get('baseTokenURI', None, _self)
    if not baseTokenURI:
        _put('baseTokenURI', _baseTokenURI, _self)

def mint(_to: address, _tokenId: uint256) -> bool:
    owner = _get('owner', None, _self)
    print('mint sender owner', _sender, owner)
    if owner != '0x0000000000000000000000000000000000000000' and owner != _sender:
        return False
    
    current_owner = _get('owners', None, _tokenId)
    if current_owner:
        return False
    _put('owners', _to, _tokenId)

    current_amount = _get('balance', 0, _to)
    new_amount = current_amount + 1
    _put('balance', new_amount, _to)

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
    _get('balance', 0, _to)

def name() -> string:
    name = _get('name', '', _self)
    print('name', name)
    return name

def symbol() -> string:
    sym = _get('symbol', '', _self)
    print('symbol', sym)
    return sym

def tokenURI(_tokenId: uint256) -> string:
    baseURI = _get('baseTokenURI', '', _self)
    URI = baseURI + _tokenId
    print('baseURI', URI)
    return URI


def supportsInterface(_interfaceId: bytes4) -> bool:
    print('bytes4', _interfaceId.hex())
    if _interfaceId.hex() == '80ac58cd': # 721
        return True
    return False


# hardhat test Account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

if __name__ == '__main__':
    for i in range(2):
        mint('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 1 * i)
    _sender = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
    transfer('0x0000000000000000000000000000000000000002', 1)
    balanceOf('0x0000000000000000000000000000000000000002')
    print(symbol())
