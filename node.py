from __future__ import print_function

import time
# import socket
# import subprocess
# import argparse
# import base64
import uuid
import threading

import tornado.web
import tornado.ioloop
import tornado.options
import tornado.httpserver
# import tornado.httpclient
# import tornado.websocket
import tornado.gen
import tornado.escape

import setting
import tree
import miner
import chain
import database

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [(r"/node", tree.NodeHandler),
                    (r"/miner", tree.MinerHandler),
                    (r"/available_branches", AvailableBranchesHandler),
                    (r"/get_node", GetNodeHandler),
                    (r"/get_highest_block_hash", chain.GetHighestBlockHashHandler),
                    (r"/get_block", chain.GetBlockHandler),
                    # (r"/get_proof", chain.GetProofHandler),
                    (r"/get_highest_subchain_block_hash", chain.GetHighestSubchainBlockHashHandler),
                    (r"/get_subchain_block", chain.GetSubchainBlockHandler),
                    (r"/new_subchain_block", NewSubchainBlockHandler),
                    (r"/dashboard", DashboardHandler),
                    (r"/chain_explorer", ChainExplorerHandler),
                    (r"/subchain_explorer", SubchainExplorerHandler),
                    (r"/user_explorer", UserExplorerHandler),
                    # (r"/disconnect", DisconnectHandler),
                    # (r"/broadcast", BroadcastHandler),
                    (r"/", MainHandler),
                    ]
        settings = {"debug":True}

        tornado.web.Application.__init__(self, handlers, **settings)

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.redirect('/dashboard')

class AvailableBranchesHandler(tornado.web.RequestHandler):
    def get(self):
        branches = list(tree.available_branches)

        # parent = tree.NodeConnector.node_parent:
        self.finish({"available_branches": branches,
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
    #     chain.new_subchain_block(["NEW_SUBCHAIN_BLOCK"] + block)
    #     tree.forward(["NEW_SUBCHAIN_BLOCK"] + block) # + [time.time(), uuid.uuid4().hex]
    #     self.finish({"block": block})

    def post(self):
        block = tornado.escape.json_decode(self.request.body)

        chain.new_subchain_block(["NEW_SUBCHAIN_BLOCK"] + block)
        tree.forward(["NEW_SUBCHAIN_BLOCK"] + block) # + [time.time(), uuid.uuid4().hex]
        self.finish({"block": block})

class DashboardHandler(tornado.web.RequestHandler):
    def get(self):
        branches = list(tree.available_branches)
        branches.sort(key=lambda l:len(l[2]))

        parents = []
        self.write("<a href='/chain_explorer'>Chain Explorer</a> ")
        self.write("<a href='/user_explorer'>User Explorer</a></br>")
        self.write("<br>current_nodeid: %s <br>" % tree.current_nodeid)

        self.write("<br>pk: %s <br>" % tree.node_sk.public_key)
        # sender = base64.b32encode(sender_vk.to_string()).decode("utf8")
        self.write("<br>node_parent:<br>")
        if tree.NodeConnector.node_parent:
            self.write("%s:%s<br>" %(tree.NodeConnector.node_parent.host, tree.NodeConnector.node_parent.port))

        self.write("<br>node_parents:<br>")
        for nodeid in tree.node_parents:
            host, port = tree.node_parents[nodeid]
            self.write("%s %s:%s<br>" %(nodeid, host, port))

        self.write("<br>node_neighborhoods:<br>")
        for nodeid in tree.node_neighborhoods:
            host, port = tree.node_neighborhoods[nodeid]
            self.write("%s %s:%s <a href='http://%s:%s/dashboard'>dashboard</a><br>" %(nodeid, host, port, host, port))

        self.write("<br>recent longest:<br>")
        for i in reversed(chain.recent_longest):
            self.write("%s <a href='/get_block?hash=%s'>%s</a> %s<br>" % (i[chain.HEIGHT], i[chain.HASH], i[chain.HASH], i[chain.IDENTITY]))

        self.write("<br>nodes_pool:<br>")
        for nodeid in tree.nodes_pool:
            pk = tree.nodes_pool[nodeid]
            self.write("%s: %s<br>" %(nodeid, pk))

        self.write("<br>nodes_in_chain:<br>")
        for nodeid in chain.nodes_in_chain:
            pk = chain.nodes_in_chain[nodeid]
            self.write("%s: %s<br>" %(nodeid, pk))

        # self.write("<br>frozen_nodes_in_chain:<br>")
        # for nodeid in chain.frozen_nodes_in_chain:
        #     pk = chain.frozen_nodes_in_chain[nodeid]
        #     self.write("%s: %s<br>" %(nodeid, pk))

        self.write("<br>available_branches:<br>")
        for branch in branches:
            self.write("%s:%s %s <br>" % branch)

        self.write("<br>subchain block to mine:<br>")
        for i, h in chain.subchains_block_to_mine.items():
            self.write("%s %s<br>" % (i, h))

        self.write("<br>pool:<br>")
        db = database.get_conn()
        it = db.iteritems()
        it.seek(b'pool')
        for k, v in it:
            if not k.startswith(b'pool'):
                break
            self.write("%s -> %s<br>"% (k[4:].decode(), v.decode()))
        self.finish()


class ChainExplorerHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument('hash', None)
        db = database.get_conn()
        if not block_hash:
            block_hash = db.get(b'chain')
        else:
            block_hash = block_hash.encode('utf8')

        if not block_hash:
            self.write('hash required')
            return

        self.write('<a href="/dashboard">Dashboard</a> ')
        self.write('<a href="/user_explorer">User Explorer</a></br></br>')

        for i in range(10):
            block_json = db.get(b'block%s' % block_hash)
            if not block_json:
                return
            self.write("<code>%s</code><br><br>" % block_json)

            fullstate_json = db.get(b'fullstate%s' % block_hash)
            self.write("<code>%s</code><br><br><br>" % fullstate_json)

            block = tornado.escape.json_decode(block_json)
            block_hash = block[chain.PREV_HASH].encode('utf8')

        self.write("<a href='/chain_explorer?hash=%s'>Next</a><br>" % block_hash.decode('utf8'))

class SubchainExplorerHandler(tornado.web.RequestHandler):
    def get(self):
        sender = self.get_argument('sender')
        assert sender.startswith('0x') and (len(sender) == 42 or len(sender) == 66)
        hash = self.get_argument('hash', None)
        self.write("<a href='/dashboard'>Dashboard</a> ")
        self.write("<a href='/chain_explorer'>Chain Explorer</a> ")
        self.write("<a href='/user_explorer'>User Explorer</a></br></br>")

        db = database.get_conn()
        if hash is None:
            msg_hash = db.get(b'chain%s' % sender[2:].encode('utf8'))
            if not msg_hash:
                return
        else:
            msg_hash = hash.encode('utf8')

        for i in range(2000):
            msg_json = db.get(b'msg%s' % msg_hash)
            if not msg_json:
                return

            self.write("<code>%s</code><br><br>" % msg_json)
            msg = tornado.escape.json_decode(msg_json)
            msg_hash = msg[chain.PREV_HASH].encode('utf8')

        self.write("<a href='/subchain_explorer?sender=%s&hash=%s'>Next</a><br>" % (sender, msg_hash.decode('utf8')))


class UserExplorerHandler(tornado.web.RequestHandler):
    def get(self):
        db = database.get_conn()
        it = db.iteritems()
        self.write("<a href='/dashboard'>Dashboard</a> ")
        self.write("<a href='/chain_explorer'>Chain Explorer</a> <br><br>")
        it.seek(b'chain')
        for k, v in it:
            if k == b'chain':
                # self.write("<a href='/chain_explorer?hash=%s'>main chain</a><br>"% v.decode())
                continue
            if not k.startswith(b'chain'):
                break
            if len(k) == 40+5:
                self.write("<a href='/subchain_explorer?sender=%s'>%s</a> %s<br>"% (k.decode().replace('chain', '0x'), k.decode().replace('chain', 'Account 0x'), v.decode()))
            elif len(k) == 64+5:
                self.write("<a href='/subchain_explorer?sender=%s'>%s</a> %s<br>"% (k.decode().replace('chain', '0x'), k.decode().replace('chain', 'Contract 0x'), v.decode()))


def main():
    tree.main()

    # miner.main()
    tornado.ioloop.IOLoop.instance().call_later(1, miner.looping)

    # leader.main()
    # tornado.ioloop.IOLoop.instance().call_later(1, leader.mining)

    # fs.main()

    worker_threading = threading.Thread(target=miner.worker_thread)
    worker_threading.start()
    chain.worker_thread_pause = False

    server = Application()
    server.listen(tree.current_port, '0.0.0.0')
    tornado.ioloop.IOLoop.instance().start()

    worker_threading.join()

if __name__ == '__main__':
    main()

