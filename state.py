
import tornado.escape

import console
import contracts


CONTRACT_ADDRESS = '0x0000000000000000000000000000000000000001'

contract_address = CONTRACT_ADDRESS


class State:
    def __init__(self, db):
        self.db = db
        self.block_number = 0
        self.pending_state = {}

    # def __setitem__(self, key, value):
    def put(self, key, value, addr=contract_address):
        value_json = tornado.escape.json_encode(value)
        console.log('globalstate_%s_%s_%s_%s' % (contract_address, key, addr, str(10**15 - self.block_number).zfill(16)), value_json)
        self.pending_state['globalstate_%s_%s_%s_%s' % (contract_address, key, addr, self.block_number)] = value_json

    # def __getitem__(self, key):
    def get(self, key, default, addr=contract_address):
        value = default
        console.log(self.pending_state)
        k = 'globalstate_%s_%s_%s_%s' % (contract_address, key, addr, self.block_number)
        console.log(k)
        if k in self.pending_state:
            value_json = self.pending_state[k]
            value = tornado.escape.json_decode(value_json)
            return value

        try:
            it = self.db.iteritems()
            it.seek(('globalstate_%s_%s_%s' % (contract_address, key, addr)).encode('utf8'))

            # value_json = _trie.get(b'state_%s_%s' % (contract_address, key.encode('utf8')))
            for k, value_json in it:
                if k.startswith(('globalstate_%s_%s_%s' % (contract_address, key, addr)).encode('utf8')):
                    # block_number = 10**15 - int(k.replace(b'%s_%s_' % (contract_address, key.encode('utf8')), b''))
                    value = tornado.escape.json_decode(value_json)
                break

        except:
            pass

        return value

    def merge(self, block_hash):
        console.log('merge', self.block_number)
        for k, v in self.pending_state.items():
            console.log(k,v)
            _, contract_address, key, addr, block_number = k.split('_')
            self.db.put(('globalstate_%s_%s_%s_%s_%s' % (contract_address, key, addr, str(10**15 - int(block_number)).zfill(16), block_hash)).encode('utf8'), v.encode('utf8'))
        self.pending_state = {}

    def call(self, contract):
        console.log(contracts.contract_map[contract])
