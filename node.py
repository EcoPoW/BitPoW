
import os
import time
import hashlib
import uuid
import threading
import tracemalloc

import tornado.web
import tornado.ioloop
import tornado.options
import tornado.httpserver
import tornado.gen
import tornado.escape

import setting
import tree
import mine
import chain
import database
import eth_rpc
import contracts

tracemalloc.start()

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [(r"/node", tree.NodeHandler),
                    (r"/miner", tree.MinerHandler),
                    (r"/nodes_available", AvailableNodesHandler),
                    (r"/get_node", GetNodeHandler),

                    (r"/get_chain_latest", chain.GetChainLatestHashHandler),
                    (r"/get_chain_block", chain.GetChainBlockHandler),
                    (r"/get_state_subchains", chain.GetStateSubchainsHandler),
                    (r"/get_state_contracts", chain.GetStateContractsHandler),
                    (r"/get_pool_subchains", chain.GetPoolSubchainsHandler),
                    (r"/get_pool_blocks", chain.GetPoolBlocksHandler),

                    # (r"/get_subchain_latest", chain.GetHighestSubchainBlockHashHandler),
                    # (r"/get_highest_subchain_block_state", chain.GetHighestSubchainBlockStateHandler),
                    # (r"/get_subchain_block", chain.GetSubchainBlockHandler),
                    # (r"/get_subchain_block_state", chain.GetSubchainBlockStateHandler),
                    (r"/new_subchain_block", NewSubchainBlockHandler),
                    (r"/new_subchain_block_batch", NewSubchainBlockBatchHandler),

                    (r"/dashboard", DashboardHandler),
                    (r"/chain_blocks", ChainBlocksHandler),
                    (r"/chain_block", ChainBlockHandler),
                    (r"/contract_list", ContractListHandler),
                    # (r"/subchain_list", SubchainListHandler),
                    # (r"/subchain_blocks", SubchainBlocksHandler),

                    (r"/scan/address/(.*)", ScanAddressHandler),
                    (r"/scan/tx/(.*)", ScanTxHandler),

                    # (r"/disconnect", DisconnectHandler),
                    # (r"/broadcast", BroadcastHandler),
                    # (r"/upload_chunk", UploadChunkHandler),
                    (r"/tracemalloc", TraceHandler),
                    # (r"/eth_rpc", eth_rpc.EthRpcHandler),
                    # (r"/", eth_rpc.ProxyEthRpcHandler),
                    (r"/", eth_rpc.EthRpcHandler),
                    # (r"/", MainHandler),
                ]
        settings = {"debug":True}

        tornado.web.Application.__init__(self, handlers, **settings)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.redirect('/dashboard')

class ScanAddressHandler(tornado.web.RequestHandler):
    def get(self, addr):
        self.finish('%s' % addr)

class ScanTxHandler(tornado.web.RequestHandler):
    def get(self, tx):
        self.finish('%s' % tx)

class AvailableNodesHandler(tornado.web.RequestHandler):
    def get(self):
        nodes = list(tree.nodes_available)

        # parent = tree.NodeConnector.node_parent:
        self.finish({"nodes_available": nodes,
                     #"parent": parent,
                     "nodeid": tree.current_nodeid})


class GetNodeHandler(tornado.web.RequestHandler):
    def get(self):
        nodeid = self.get_argument("nodeid")
        target_nodeid = nodeid
        score = None
        address = [tree.current_host, tree.current_port]
        # print(tree.current_port, tree.node_neighborhoods)
        for j in [tree.node_neighborhoods, tree.node_parents]:
            for i in j:
                new_score = tree.node_distance(nodeid, i)
                if score is None or new_score < score:
                    score = new_score
                    target_nodeid = i
                    address = j[target_nodeid]
                # print(i, new_score)

        self.finish({"address": address,
                     "nodeid": target_nodeid,
                     "current_nodeid": tree.current_nodeid})


class DisconnectHandler(tornado.web.RequestHandler):
    def get(self):
        if tree.NodeConnector.node_parent:
            # connector.remove_node = False
            tree.NodeConnector.node_parent.close()

        self.finish({})
        tornado.ioloop.IOLoop.instance().stop()


class BroadcastHandler(tornado.web.RequestHandler):
    def get(self):
        test_msg = ["TEST_MSG", tree.current_nodeid, time.time(), uuid.uuid4().hex]

        tree.forward(test_msg)
        self.finish({"test_msg": test_msg})


class NewSubchainBlockHandler(tornado.web.RequestHandler):
    # def get(self):
    #     block =  ["58745b596bcfc8376527fd37cb2ca34224ff4d1d4f1d41053a889742f4bc77a8", "0000000000000000000000000000000000000000000000000000000000000000", "0xb88744C14D2E92cC653493df18bEF2E4b263c1FD", "0x504E18e367F32050951452Affc56082847628d28", 1, {"amount": 6}, 1633745105.8568707, "0x64a7f9a8b19cfd7597ecc6a49ada434b2101a7a8afc0ac78e59a59af3152eedc1a26e9a9b660373b8eae7bc2c646b393f0a51bd904e5a16336ebc3c3d77710c401"]
    #     chain.new_subchain_block(['NEW_SUBCHAIN_BLOCK'] + block)
    #     tree.forward(['NEW_SUBCHAIN_BLOCK'] + block) # + [time.time(), uuid.uuid4().hex]
    #     self.finish({"block": block})

    def post(self):
        block = tornado.escape.json_decode(self.request.body)

        chain.new_subchain_block(['NEW_SUBCHAIN_BLOCK'] + block)
        tree.forward(['NEW_SUBCHAIN_BLOCK'] + block) # + [time.time(), uuid.uuid4().hex]
        self.finish({"block": block})


class NewSubchainBlockBatchHandler(tornado.web.RequestHandler):
    def post(self):
        blocks = tornado.escape.json_decode(self.request.body)
        for block in blocks:
            chain.new_subchain_block(['NEW_SUBCHAIN_BLOCK'] + block)
            tree.forward(['NEW_SUBCHAIN_BLOCK'] + block) # + [time.time(), uuid.uuid4().hex]
        # self.finish({"block": block})
        self.finish({})


class DashboardHandler(tornado.web.RequestHandler):
    def get(self):
        nodes_available = list(tree.nodes_available)
        nodes_available.sort(key=lambda l:len(l[2]))

        parents = []
        self.write('<a href="/chain_blocks">Chain view</a> ')
        self.write('<a href="/contract_list">Contract list</a> ')
        # self.write('<a href="/subchain_list">Subchain list</a> ')
        # self.write('<a href="/tempchain_list">Temp list</a>')
        self.write('<br><br>current_nodeid: %s <br>' % tree.current_nodeid)

        self.write('<br>pk: %s <br>' % tree.node_sk.public_key)
        self.write('address: %s <br>' % tree.node_sk.public_key.to_checksum_address())
        # sender = base64.b32encode(sender_vk.to_string()).decode("utf8")
        self.write('<br>node_parent:<br>')
        if tree.NodeConnector.node_parent:
            self.write('%s:%s<br>' %(tree.NodeConnector.node_parent.host, tree.NodeConnector.node_parent.port))

        self.write('<br>node_parents:<br>')
        for nodeid in tree.node_parents:
            host, port = tree.node_parents[nodeid]
            self.write('%s %s:%s <a href="http://%s:%s/dashboard">dashboard</a><br>' %(nodeid, host, port, host, port))

        self.write('<br>node_neighborhoods:<br>')
        for nodeid in tree.node_neighborhoods:
            host, port = tree.node_neighborhoods[nodeid]
            self.write('%s %s:%s <a href="http://%s:%s/dashboard">dashboard</a><br>' %(nodeid, host, port, host, port))

        self.write('<br>recent longest:<br>')
        for i in reversed(chain.recent_longest):
            self.write('%s <a href="/get_block?hash=%s">%s</a> %s<br>' % (i[chain.HEIGHT], i[chain.HASH], i[chain.HASH], i[chain.IDENTITY]))

        self.write('<br>nodes_pool:<br>')
        for nodeid in tree.nodes_pool:
            pk = tree.nodes_pool[nodeid]
            self.write("%s: %s<br>" %(nodeid, pk))

        self.write('<br>nodes_in_chain:<br>')
        for nodeid in chain.nodes_in_chain:
            pk = chain.nodes_in_chain[nodeid]
            self.write("%s: %s<br>" %(nodeid, pk))

        # self.write('<br>frozen_nodes_in_chain:<br>')
        # for nodeid in chain.frozen_nodes_in_chain:
        #     pk = chain.frozen_nodes_in_chain[nodeid]
        #     self.write('%s: %s<br>' %(nodeid, pk))

        self.write('<br>nodes_available:<br>')
        for branch in nodes_available:
            self.write("%s:%s %s <br>" % branch)

        # self.write('<br>subchain block to mine:<br>')
        # for i, h in chain.subchains_to_block.items():
        #     self.write("%s %s<br>" % (i, h))

        self.write('<br>pool:<br>')
        db = database.get_conn()
        it = db.iteritems()
        it.seek(b'pool')
        for k, v in it:
            if not k.startswith(b'pool'):
                break
            self.write("%s -> %s<br>"% (k[4:].decode(), v.decode()))
        self.finish()


class ChainBlocksHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('<a href="/dashboard">Dashboard</a> ')
        # self.write('<a href="/subchain_list">Subchain list</a> ')
        # self.write('<a href="/tempchain_list">Temp list</a>')
        self.write('</br></br>')

        block_height = self.get_argument('height', None)
        current_height = None
        db = database.get_conn()
        it = db.iteritems()
        if block_height:
            it.seek(('headerblock_%s' % str(setting.REVERSED_NO-int(block_height)).zfill(16)).encode('utf8'))
        else:
            it.seek(b'headerblock_')
        for key, value in it:
            if not key.decode('utf8').startswith('headerblock_'):
                break
            header = tornado.escape.json_decode(value)
            block_hash = header[0]
            header_data = header[1]
            height = header_data['height']
            if not current_height:
                current_height = height
                self.write('<a href="/chain_blocks?height=%s">Prev</a> ' % (current_height+10))
                self.write('<a href="/chain_blocks?height=%s">Next</a> ' % (current_height-10))
                self.write('<br><br>')
            self.write("<a href='/chain_block?height=%s&hash=%s'>%s</a><br>" % (height, block_hash, key, ))
            self.write("%s<br><br>" % (header_data, ))
            self.write("%s<br><br>" % (value, ))
            if height + 9 <= current_height:
                break


class ChainBlockHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash= self.get_argument('hash', None)
        block_height = self.get_argument('height', None)

        self.write('<a href="/dashboard">Dashboard</a> ')
        # self.write('<a href="/subchain_list">Subchain list</a> ')
        # self.write('<a href="/tempchain_list">Temp list</a>')
        self.write('</br></br>')

        db = database.get_conn()
        txbody = db.get(('txbody_%s_%s' % (str(setting.REVERSED_NO-int(block_height)).zfill(16), block_hash)).encode('utf8'))
        txs = tornado.escape.json_decode(txbody)
        for addr, height, subchain_hash in txs:
            self.write("<a href='/get_pool_blocks?addr=%s&to_no=%s&to_hash=%s'>%s</a> <a href='/get_state_subchains?addrs=%s&height=%s'>%s</a> %s<br>" % (addr, height, subchain_hash, addr, addr, int(block_height)-1, subchain_hash, height))
        self.write("<br>")
        self.write("%s<br><br>" % (txbody, ))
        statebody = db.get(('statebody_%s_%s' % (str(setting.REVERSED_NO-int(block_height)).zfill(16), block_hash)).encode('utf8'))
        self.write("%s<br><br>" % (statebody, ))


# class SubchainBlocksHandler(tornado.web.RequestHandler):
#     def get(self):
#         sender = self.get_argument('sender')
#         assert len(sender) == 42 and (sender.startswith('0x') or sender.startswith('1x'))
#         hash = self.get_argument('hash', None)
#         self.write('<a href="/dashboard">Dashboard</a> ')
#         self.write('<a href="/chain_blocks">Chain view</a> ')
#         # self.write('<a href="/subchain_list">Subchain list</a> ')
#         # self.write('<a href="/tempchain_list">Temp list</a>')
#         self.write('</br></br>')

#         db = database.get_conn()
#         if hash is None:
#             msg_hash = db.get(b'chain_%s' % sender.encode('utf8'))
#             if not msg_hash:
#                 return
#         else:
#             msg_hash = hash.encode('utf8')

#         for i in range(2000):
#             msg_json = db.get(b'msg_%s' % msg_hash)
#             if not msg_json:
#                 return

#             msg = tornado.escape.json_decode(msg_json)
#             self.write("<a href='/get_subchain_block_state?hash=%s'>%s</a><br>" % (msg[0], msg[4]))
#             self.write("<code>%s</code><br><br>" % msg_json)
#             msg_hash = msg[chain.PREV_HASH].encode('utf8')

#         self.write("<a href='/subchain_blocks?sender=%s&hash=%s'>Next</a><br>" % (sender, msg_hash.decode('utf8')))


# class SubchainListHandler(tornado.web.RequestHandler):
#     def get(self):
#         db = database.get_conn()
#         it = db.iteritems()
#         self.write('<a href="/dashboard">Dashboard</a> ')
#         self.write('<a href="/chain_blocks">Chain view</a> ')
#         # self.write('<a href="/tempchain_list">Temp list</a>')
#         self.write('</br></br>')
#         it.seek(b'chain_')
#         for k, v in it:
#             # if k == b'chain':
#             #     # self.write("<a href='/chain_blocks?hash=%s'>main chain</a><br>"% v.decode())
#             #     continue
#             # if not k.startswith(b'chain_'):
#             #     break
#             if len(k) == 42+6:
#                 self.write("<a href='/subchain_blocks?sender=%s'>%s</a> %s<br>"% (k.decode().replace('chain_', ''), k.decode().replace('chain_', 'Account '), v.decode()))
#             # elif len(k) == 42+6 and k.startswith(b'chain_1x'):
#             #     self.write("<a href='/subchain_blocks?sender=%s'>%s</a> %s<br>"% (k.decode().replace('chain_', ''), k.decode().replace('chain_', 'Contract '), v.decode()))


class ContractListHandler(tornado.web.RequestHandler):
    def get(self):
        db = database.get_conn()
        self.write('<a href="/dashboard">Dashboard</a> ')
        self.write('<a href="/chain_blocks">Chain view</a> ')
        # self.write('<a href="/tempchain_list">Temp list</a>')
        self.write('</br></br>')
        # it = db.iteritems()
        # it.seek(b'chain_')
        for k in contracts.contract_map:
            self.write("<a href='/get_state_contracts?addr=%s'>%s</a><br>" % (k, k))


class UploadChunkHandler(tornado.web.RequestHandler):
    def post(self):
        hash = self.get_argument('hash')
        chunk = self.request.body
        hash_verify = hashlib.sha256(chunk).hexdigest()
        assert hash_verify == hash

        if not os.path.exists('./chunks/'):
            os.mkdir('./chunks/')
        with open('./chunks/%s' % hash, 'wb') as c:
            c.write(chunk)
        self.finish({'len': len(chunk)})


class TraceHandler(tornado.web.RequestHandler):
    def get(self):
        import html
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics('lineno')

        # self.write('[ Top 20 ]<br>')
        for stat in top_stats[:20]:
            print(stat)
            stat = html.escape(str(stat))
            self.write(stat+'<br>\n')


def main():
    tree.main()

    server = Application()
    server.listen(tree.current_port, '0.0.0.0')
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()

