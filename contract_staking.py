
from contract_types import address, uint256


def stake(_value:uint256):
    print(_sender, _self, _value)
    assert _value > 0
    value = _get('staking', [0, 0], _sender)
    value[0] += _value
    value[1] = _block_number - 1
    _put('staking', value, _sender)
    _call('0x0000000000000000000000000000000000000001', 'transferFrom', [_sender, _self, _value])

def unstake(_spender:address, _value:uint256):
    pass


