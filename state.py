
import string

import tornado.escape
import web3

import contracts
import console
import database

db = None
pending_state = database.get_temp_conn()

block_number = 0
contract_address = None
sender = None

def put(_owner, _var, _value, _key = None):
    global pending_state
    global block_number
    global contract_address
    global sender

    assert type(_var) is str
    assert set(_var) - set(string.ascii_letters + string.digits + '-.') == set()
    if _key is not None:
        assert type(_key) is str
        assert set(_key) - set(string.ascii_letters + string.digits + '-.') == set()
        var = '%s[%s]' % (_var, _key)
    else:
        var = _var

    addr = _owner.lower()
    value_json = tornado.escape.json_encode(_value)
    # console.log('globalstate_%s_%s_%s_%s' % (contract_address, var, addr, str(10**15 - block_number).zfill(16)), value_json)
    k = 'globalstate_%s_%s_%s_%s' % (contract_address, var, str(10**15 - int(block_number)).zfill(16), addr)
    pending_state.put(k.encode('utf8'), value_json.encode('utf8'))

def get(_var, _default = None, _key = None):
    global pending_state
    global block_number
    global contract_address
    global sender
    #console.log(pending_state)
    #console.log(block_number)
    #console.log(contract_address)

    value = _default
    assert type(_var) is str
    assert set(_var) - set(string.ascii_letters + string.digits + '-.') == set()
    if _key is not None:
        assert type(_key) is str
        assert set(_key) - set(string.ascii_letters + string.digits + '-.') == set()
        var = '%s[%s]' % (_var, _key)
    else:
        var = _var

    k = 'globalstate_%s_%s_' % (contract_address, var)
    console.log(k)
    it = pending_state.iteritems()
    for k, value_json in it:
        if k.startswith(('globalstate_%s_%s_' % (contract_address, var)).encode('utf8')):
            value = tornado.escape.json_decode(value_json)
            return value
        break

    it = db.iteritems()
    # console.log(('globalstate_%s_%s_%s' % (contract_address, var, addr)).encode('utf8'))
    it.seek(('globalstate_%s_%s_' % (contract_address, var)).encode('utf8'))

    # value_json = _trie.get(b'state_%s_%s' % (contract_address, var.encode('utf8')))
    for k, value_json in it:
        if k.startswith(('globalstate_%s_%s_' % (contract_address, var)).encode('utf8')):
            # block_number = 10**15 - int(k.replace(b'%s_%s_' % (contract_address, var.encode('utf8')), b''))
            # console.log(k, value_json)
            # try:
            value = tornado.escape.json_decode(value_json)
            # except:
            #     pass
        break

    return value

def call(_addr, fn, params):
    global block_number
    global contract_address
    global sender

    addr = _addr.lower()
    # console.log(addr, fn, params)
    # console.log(contracts.vm_map[addr])
    func_params = []
    for k, v in zip(contracts.params_map[addr][fn], params):
        print('type', k, v)
        if k == 'address':
            func_params.append(web3.Web3.to_checksum_address(v))
        elif k == 'uint256':
            func_params.append(v)

    contracts.vm_map[addr].global_vars['_block_number'] = block_number
    contracts.vm_map[addr].global_vars['_call'] = call
    contracts.vm_map[addr].global_vars['_get'] = get
    contracts.vm_map[addr].global_vars['_put'] = put
    contracts.vm_map[addr].global_vars['_sender'] = sender.lower()
    contract_address = addr
    contracts.vm_map[addr].global_vars['_self'] = contract_address
    contracts.vm_map[addr].run(func_params, fn)
    return

def merge(_block_hash, _pending_state):
    global db
    global pending_state
    # console.log('merge')
    for k, v in _pending_state.items():
        # console.log(k,v)
        _, contract_address, var, block_number, addr = k.split('_')
        db.put(('globalstate_%s_%s_%s_%s_%s' % (contract_address, var, str(10**15 - int(block_number)).zfill(16), _block_hash, addr)).encode('utf8'), v.encode('utf8'))
    pending_state = database.get_temp_conn()


def dump():
    global pending_state
    it = pending_state.iteritems()
    it.seek_to_first()
    statebody = {}
    for k, v in it:
        console.log(k, v)
        storage_key, contract_address, var, block_number, addr = k.decode('utf8').split('_')
        key = '%s_%s_%s_%s_%s' % (storage_key, contract_address, var, 10**15 - int(block_number), addr)
        statebody[key] = v.decode('utf8')
    return statebody

# _state = None
def init_state(d):
    global db
    # global _state
    db = d
    # _state = State()

# def get_state():
#     global _state
#     return _state


