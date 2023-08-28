
import tornado.escape

#import database


class address(str):pass
class uint256(int):pass


CONTRACT_ADDRESS = '0x0000000000000000000000000000000000000001'

contract_address = CONTRACT_ADDRESS


#_trie = database.get_conn()
block_number = 0

class State:
    # def __setitem__(self, key, value):
    def put(self, key, value):
        #global _trie
        global block_number
        value_json = tornado.escape.json_encode(value)
        print('state_%s_%s_%s' % (contract_address, key, str(10**15 - block_number).zfill(16)), value_json)
        self.db.put(('state_%s_%s_%s' % (contract_address, key, str(10**15 - block_number).zfill(16))).encode('utf8'), value_json.encode('utf8'))


    # def __getitem__(self, key):
    def get(self, key, default):
        #global _trie
        # print('_trie', _trie)
        value = default
        # block_number = 0
        try:
            it = self.db.iteritems()
            it.seek(('state_%s_%s' % (contract_address, key)).encode('utf8'))

            # value_json = _trie.get(b'state_%s_%s' % (contract_address, key.encode('utf8')))
            for k, value_json in it:
                if k.startswith(('state_%s_%s' % (contract_address, key)).encode('utf8')):
                    # block_number = 10**15 - int(k.replace(b'%s_%s_' % (contract_address, key.encode('utf8')), b''))
                    value = tornado.escape.json_decode(value_json)
                break

        except:
            pass

        return value

#_state = State()

