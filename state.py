
import tornado.escape
import web3

import contracts
import console
import database

db = None
pending_state = {}
class State:
    def __init__(self):
        self.block_number = 0
        self.contract_address = None
        self.sender = None

    # def __setitem__(self, key, value):
    def put(self, key, value, addr):
        global pending_state
        value_json = tornado.escape.json_encode(value)
        # console.log('globalstate_%s_%s_%s_%s' % (self.contract_address, key, addr, str(10**15 - self.block_number).zfill(16)), value_json)
        pending_state['globalstate_%s_%s_%s_%s' % (self.contract_address, key, addr, self.block_number)] = value_json

    # def __getitem__(self, key):
    def get(self, key, default, addr):
        global pending_state
        value = default
        # console.log(self.block_number)
        # console.log(self.contract_address)
        # console.log(pending_state)
        k = 'globalstate_%s_%s_%s_%s' % (self.contract_address, key, addr, self.block_number)
        # console.log(k)
        if k in pending_state:
            value_json = pending_state[k]
            # console.log(value_json)
            value = tornado.escape.json_decode(value_json)
            return value

        it = db.iteritems()
        # console.log(('globalstate_%s_%s_%s' % (self.contract_address, key, addr)).encode('utf8'))
        it.seek(('globalstate_%s_%s_%s' % (self.contract_address, key, addr)).encode('utf8'))

        # value_json = _trie.get(b'state_%s_%s' % (contract_address, key.encode('utf8')))
        for k, value_json in it:
            if k.startswith(('globalstate_%s_%s_%s' % (self.contract_address, key, addr)).encode('utf8')):
                # block_number = 10**15 - int(k.replace(b'%s_%s_' % (contract_address, key.encode('utf8')), b''))
                # console.log(k, value_json)
                # try:
                value = tornado.escape.json_decode(value_json)
                # except:
                #     pass
            break

        return value

def call(addr, fn, params):
    # console.log(addr, fn, params)
    # console.log(contracts.vm_map[addr])
    func_params = []
    for k, v in zip(contracts.params_map[addr][fn], params):
        print('type', k, v)
        if k == 'address':
            func_params.append(web3.Web3.to_checksum_address(v))
        elif k == 'uint256':
            func_params.append(v)

    contracts.vm_map[addr].global_vars['_block_number'] = _state.block_number
    contracts.vm_map[addr].global_vars['_call'] = call
    contracts.vm_map[addr].global_vars['_state'] = _state
    contracts.vm_map[addr].global_vars['_sender'] = _state.sender
    _state.contract_address = addr
    contracts.vm_map[addr].global_vars['_self'] = _state.contract_address
    contracts.vm_map[addr].run(func_params, fn)
    return

def merge(block_hash, pending_state):
    global db
    # console.log('merge')
    for k, v in pending_state.items():
        # console.log(k,v)
        _, contract_address, key, addr, block_number = k.split('_')
        db.put(('globalstate_%s_%s_%s_%s_%s' % (contract_address, key, addr, str(10**15 - int(block_number)).zfill(16), block_hash)).encode('utf8'), v.encode('utf8'))
    pending_state = {}

_state = None
def init_state(d):
    global db
    global _state
    db = d
    _state = State()

def get_state():
    global _state
    return _state


