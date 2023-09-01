
import os
import sys
import math
import time
import socket
import subprocess
import argparse
import uuid
import functools
import base64
import secrets

import tornado.web
import tornado.websocket
import tornado.ioloop
import tornado.httpclient
import tornado.gen
import tornado.escape

import setting
import mine
import chain
import database
import eth_rpc
import console

# import ecdsa
import eth_keys

dashboard_port = 0

current_name = None
current_host = None
current_port = None
current_nodeid = None
node_sk = None
parent_host = None
parent_port = None
dashboard_host = None
dashboard_port = None
bootstrap_url = None

current_branch = None
nodes_available = set()

node_neighborhoods = dict()
node_parents = dict()
nodes_pool = dict()
parent_node_id_msg = None

processed_message_ids = set()
processed_message_queue = []

def forward(seq):
    global processed_message_ids
    global processed_message_queue
    if processed_message_queue and processed_message_queue[0][1] < time.time() - 60:
        msg_id, msg_timestamp = processed_message_queue.pop(0)
        if msg_id in processed_message_ids:
            processed_message_ids.remove(msg_id)

    message_id = seq[-1]
    if message_id in processed_message_ids:
        return
    processed_message_ids.add(message_id)
    processed_message_queue.append((message_id, time.time()))

    message = tornado.escape.json_encode(seq)

    for k, child_node in NodeHandler.child_nodes.items():
        # if not child_node.stream.closed:
        try:
            child_node.write_message(message)
        except tornado.websocket.WebSocketClosedError:
            del NodeHandler.child_nodes[k]

    if NodeConnector.node_parent:
        NodeConnector.node_parent.conn.write_message(message)

    if MinerHandler.child_miners:
        for child_miner in MinerHandler.child_miners:
            child_miner.write_message(message)

def nodeid2no(nodeid):
    if not nodeid:
        return 1
    return 2**len(str(nodeid)) + int(nodeid, 2)

def nodeno2id(nodeno):
    if nodeno < 2:
        return ''
    no = int(math.log(nodeno, 2))
    return bin(nodeno - 2**no)[2:].zfill(no)

def node_distance(a, b):
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a):
        if a[i] != b[i]:
            break
        i += 1
    return len(a)+len(b)-i*2

def sign_msg(message):
    global node_sk
    if not node_sk:
        raise
    message_json = tornado.escape.json_encode(message)
    signature = node_sk.sign_msg(message_json.encode("utf8"))
    message.append(signature.to_hex())
    print(current_port, "signature", message)


class MinerHandler(tornado.websocket.WebSocketHandler):
    child_miners = set()

    def check_origin(self, origin):
        return True

    def open(self):
        if self not in MinerHandler.child_miners:
            MinerHandler.child_miners.add(self)

        console.log(current_port)

    def on_close(self):
        console.log(current_port)
        if self in MinerHandler.child_miners:
            MinerHandler.child_miners.remove(self)

    @tornado.gen.coroutine
    def on_message(self, message):
        print('on_message', message)
        seq = tornado.escape.json_decode(message)
        if seq[0] == 'GET_MINER_NODE':
            print("MinerHandler GET_MINER_NODE", seq, current_nodeid)
            self.write_message(tornado.escape.json_encode(["MINER_NODE_ID", current_nodeid]))

        elif seq[0] == 'NEW_CHAIN_STAKING':
            pass

        elif seq[0] == 'NEW_CHAIN_BLOCK':
            print("MinerHandler NEW_CHAIN_BLOCK", seq)
            chain.new_chain_block(seq)

        elif seq[0] == "NEW_CHAIN_HEADER":
            print("MinerHandler got NEW_CHAIN_HEADER", seq)
            chain.new_chain_header(seq)

        elif seq[0] == "NEW_CHAIN_TXBODY":
            print("MinerHandler got NEW_CHAIN_TXBODY", seq)
            chain.new_chain_txbody(seq)

        elif seq[0] == "NEW_CHAIN_STATEBODY":
            print("MinerHandler got NEW_CHAIN_STATEBODY", seq)
            chain.new_chain_statebody(seq)

        # elif seq[0] == 'NEW_SUBCHAIN_BLOCK':
        #     print("MinerHandler NEW_SUBCHAIN_BLOCK", seq)
        #     chain.new_subchain_block(seq)

        forward(seq)


# connect point from child node
class NodeHandler(tornado.websocket.WebSocketHandler):
    child_nodes = dict()

    def check_origin(self, origin):
        return True

    def open(self):
        global node_parents

        self.from_host = self.get_argument("host")
        self.from_port = self.get_argument("port")
        self.pk = self.get_argument("pk")
        self.sig = self.get_argument("sig")
        print(self.pk, len(self.pk))
        pk_bytes = bytes.fromhex(self.pk[2:])
        child_pk = eth_keys.keys.PublicKey(pk_bytes)
        sig = eth_keys.keys.Signature(bytes.fromhex(self.sig[2:]))
        child_pk.verify_msg(b"%s%s%s" % (self.from_host.encode("utf8"), self.from_port.encode("utf8"), pk_bytes), sig)
        # TODO: disconnect if not verified

        self.remove_node = True
        if current_nodeid + '0' not in NodeHandler.child_nodes:
            self.branch = current_nodeid + '0'
        elif current_nodeid + '1' not in NodeHandler.child_nodes:
            self.branch = current_nodeid + '1'
        else:
            self.branch = None

            print(current_port, "force disconnect")
            self.remove_node = False
            self.close()

            if tuple([self.from_host, self.from_port, self.branch]) in nodes_available:
                nodes_available.remove(tuple([self.from_host, self.from_port, self.branch]))

            message = ["NODE_LEFT", self.from_host, self.from_port, self.branch, uuid.uuid4().hex]
            forward(message)
            return

        print(current_port, "child connected branch", self.branch)
        if self.branch not in NodeHandler.child_nodes:
            NodeHandler.child_nodes[self.branch] = self

        timestamp = time.time()
        message = ['NODE_JOIN', self.branch, self.pk, self.from_host, self.from_port,
                    current_nodeid, node_sk.public_key.to_hex(), current_host, current_port, timestamp]
        sign_msg(message)
        forward(message)
        # self.write_message(tornado.escape.json_encode(message))

        print('====', self.from_host, self.from_port, self.branch)
        if tuple([self.from_host, self.from_port, self.branch]) not in nodes_available:
            nodes_available.add(tuple([self.from_host, self.from_port, self.branch]))

        node_parents[current_nodeid] = [current_host, current_port]
        message = ["NODE_PARENTS", node_parents, uuid.uuid4().hex]
        self.write_message(tornado.escape.json_encode(message))

        message = ["NODE_NEIGHBOURHOODS", current_nodeid, [current_host, current_port], uuid.uuid4().hex]
        self.write_message(tornado.escape.json_encode(message))

    def on_close(self):
        print(current_port, "child disconnected from parent")
        if self.branch in NodeHandler.child_nodes and self.remove_node:
            del NodeHandler.child_nodes[self.branch]
        self.remove_node = True

        if tuple([self.from_host, self.from_port, self.branch]) in nodes_available:
            nodes_available.remove(tuple([self.from_host, self.from_port, self.branch]))

        message = ["NODE_LEFT", self.from_host, self.from_port, self.branch, uuid.uuid4().hex]
        forward(message)

        if self.branch in nodes_pool:
            del nodes_pool[self.branch]

    @tornado.gen.coroutine
    def on_message(self, message):
        global current_nodeid
        global node_neighborhoods
        global nodes_pool

        seq = tornado.escape.json_decode(message)
        # # print(current_port, "on message from child", seq)
        if seq[0] == 'NODE_JOIN':
            nodeid = seq[1]
            pk = seq[2]
            ip = seq[3]
            port = seq[4]
            parent_nodeid = seq[5]
            parent_pk = seq[6]
            parent_ip = seq[7]
            parent_port = seq[8]
            timestamp = seq[9]
            singature = seq[10]

            if parent_nodeid == "":
                nodes_pool[parent_nodeid] = [parent_pk, parent_ip, parent_port, timestamp]
            if ip and port:
                nodes_pool[nodeid] = [pk, ip, port, timestamp]
            else:
                del nodes_pool[nodeid]
            nodes_available.add(tuple([ip, port, nodeid]))
            print(current_port, 'NODE_JOIN', nodeid, pk, parent_nodeid, parent_pk, seq[-1])

        elif seq[0] == "NODE_LEFT":
            _, branch_host, branch_port, branch, _ = seq
            if tuple([branch_host, branch_port, branch]) in nodes_available:
                nodes_available.remove(tuple([branch_host, branch_port, branch]))

        elif seq[0] == "NODE_NEIGHBOURHOODS":
            nodeid = seq[1]
            if current_nodeid is not None and node_distance(nodeid, current_nodeid) > setting.NEIGHBOURHOODS_HOPS:
                return
            node_neighborhoods[nodeid] = tuple(seq[2])
            # print(current_port, "NODE_NEIGHBOURHOODS", current_nodeid, nodeid, node_neighborhoods)

        elif seq[0] == "NEW_CHAIN_BLOCK":
            print("NEW_CHAIN_BLOCK", seq)
            chain.new_chain_block(seq)

        elif seq[0] == 'NEW_SUBCHAIN_BLOCK':
            chain.new_subchain_block(seq)
            # msg.WaitMsgHandler.new_block(seq)

        forward(seq)


# connector to parent node
class NodeConnector(object):
    """Websocket Client"""
    node_parent = None

    def __init__(self, to_host, to_port):
        global node_sk
        self.host = to_host
        self.port = to_port
        # self.branch = branch
        self.pk = node_sk.public_key

        # print(self.pk)
        # print(b"%s%s%s%s" % (self.branch.encode("utf8"), current_host.encode("utf8"), current_port.encode("utf8"), self.pk))
        sig = node_sk.sign_msg(b"%s%s%s" % (current_host.encode("utf8"), current_port.encode("utf8"), self.pk.to_bytes()))
        # print(sig)
        self.ws_uri = "ws://%s:%s/node?host=%s&port=%s&pk=%s&sig=%s" % (self.host, self.port, current_host, current_port, self.pk.to_hex(), sig.to_hex())
        self.conn = None
        self.connect()

    def connect(self):
        tornado.websocket.websocket_connect(self.ws_uri,
                                callback = self.on_connect,
                                on_message_callback = self.on_message,
                                connect_timeout = 1000.0,
                                ping_timeout = 600.0
                            )

    def close(self):
        if NodeConnector.node_parent:
            NodeConnector.node_parent = None
        self.conn.close()

    @tornado.gen.coroutine
    def on_connect(self, future):
        print(current_port, "node connect", current_nodeid)

        try:
            self.conn = future.result()
            if not NodeConnector.node_parent:
                NodeConnector.node_parent = self

        except:
            print(current_port, "NodeConnector reconnect ...")
            tornado.ioloop.IOLoop.instance().call_later(1.0, self.connect)
            # tornado.ioloop.IOLoop.instance().call_later(1.0, bootstrap)
            # tornado.ioloop.IOLoop.instance().call_later(1.0, functools.partial(bootstrap, (self.host, self.port)))
            return

    @tornado.gen.coroutine
    def on_message(self, message):
        global current_branch
        global current_nodeid
        global node_parents
        global node_neighborhoods
        global nodes_pool
        global parent_node_id_msg

        if message is None:
            print("NodeConnector reconnect ...")
            tornado.ioloop.IOLoop.instance().call_later(1.0, self.connect)
            return

        seq = tornado.escape.json_decode(message)
        if seq[0] == 'NODE_JOIN':
            nodeid = seq[1]
            pk = seq[2]
            ip = seq[3]
            port = seq[4]
            parent_nodeid = seq[5]
            parent_pk = seq[6]
            parent_ip = seq[7]
            parent_port = seq[8]
            timestamp = seq[9]
            singature = seq[10]
            print('====NodeConnector', seq)

            if parent_nodeid is not None:
                nodes_pool[parent_nodeid] = [parent_pk, parent_ip, parent_port, timestamp]
                node_parents[parent_nodeid] = [self.host, self.port]
                chain.nodes_to_fetch.add(parent_nodeid)
            nodes_pool[nodeid] = [pk, ip, port, timestamp]
            print(current_port, 'NODE_JOIN', nodeid, pk, 'PARENT_ID', parent_nodeid, parent_pk, seq[-1])
            current_nodeid = nodeid
            nodes_available.add(tuple([ip, port, nodeid]))

            if current_nodeid is not None:
                message = ["NODE_NEIGHBOURHOODS", current_nodeid, [current_host, current_port], uuid.uuid4().hex]
                self.conn.write_message(tornado.escape.json_encode(message))

            # print(current_port, "NODE_PARENTS", node_parents[current_nodeid])
            if self.conn and not self.conn.stream.closed:
                message = ["NODE_NEIGHBOURHOODS", current_nodeid, [current_host, current_port], uuid.uuid4().hex]
                self.conn.write_message(tornado.escape.json_encode(message))

            parent_node_id_msg = seq

            if control_node:
                control_node.write_message(tornado.escape.json_encode(["ADDRESS2", current_host, current_port, current_nodeid]))

            # return

        elif seq[0] == "NODE_LEFT":
            _, branch_host, branch_port, branch, _ = seq
            if tuple([branch_host, branch_port, branch]) in nodes_available:
                nodes_available.remove(tuple([branch_host, branch_port, branch]))

        elif seq[0] == "NODE_PARENTS":
            node_parents.update(seq[1])
            # print(current_port, "NODE_PARENTS", node_parents)

            for child_node in NodeHandler.child_nodes.values():
                child_node.write_message(message)
            return

        elif seq[0] == "NODE_NEIGHBOURHOODS":
            nodeid = seq[1]
            print('nodeid', nodeid)
            if nodeid is None or current_nodeid is None:
                return
            if node_distance(nodeid, current_nodeid) > setting.NEIGHBOURHOODS_HOPS:
                return
            node_neighborhoods[nodeid] = tuple(seq[2])
            # print(current_port, "NODE_NEIGHBOURHOODS", current_nodeid, nodeid, node_neighborhoods)

        elif seq[0] == "NEW_CHAIN_BLOCK":
            print("NEW_CHAIN_BLOCK", seq)
            chain.new_chain_block(seq)

        elif seq[0] == 'NEW_SUBCHAIN_BLOCK':
            chain.new_subchain_block(seq)
            # msg.WaitMsgHandler.new_block(seq)

        forward(seq)

# @tornado.gen.coroutine
# def bootstrap(addr):
#     global nodes_available

#     print(current_port, 'fetch available nodes', addr)
#     http_client = tornado.httpclient.AsyncHTTPClient()
#     try:
#         response = yield http_client.fetch('http://%s:%s/nodes_available' % tuple(addr))
#     except Exception as e:
#         print('bootstrap Error: %s' % e)
#         tornado.ioloop.IOLoop.instance().call_later(1.0, functools.partial(bootstrap, addr))
#         return

#     result = tornado.escape.json_decode(response.body)
#     nodes = result['nodes_available']
#     nodes.sort(key=lambda l:len(l[2]))
#     print(current_port, '  fetch result', [tuple(i) for i in nodes])

#     if nodes:
#         nodes_available = set([tuple(i) for i in nodes])
#         host, port, branch = nodes[0]
#         current_branch = tuple(nodes[0])
#         NodeConnector(host, port, branch)
#     else:
#         tornado.ioloop.IOLoop.instance().call_later(1.0, functools.partial(bootstrap, addr))

# connector to control center
control_node = None
@tornado.gen.coroutine
def control_on_connect(future):
    global control_node

    try:
        control_node = future.result()
        control_node.write_message(tornado.escape.json_encode(["ADDRESS", current_host, current_port]))
    except:
        tornado.ioloop.IOLoop.instance().call_later(1.0, connect)

@tornado.gen.coroutine
def control_on_message(msg):
    global current_nodeid
    global nodes_available

    if msg is None:
        tornado.ioloop.IOLoop.instance().call_later(1.0, connect)
        return

    seq = tornado.escape.json_decode(msg)
    print(current_port, "node on message", seq)

    if setting.BOOTSTRAP_BY_PORT_NO:
        return

    if seq[0] == "BOOTSTRAP_ADDRESS":
        if not seq[1]:
            # root node
            current_nodeid = ""
            nodes_available.add(tuple([current_host, current_port, current_nodeid]))

        # else:
        #     bootstrap(seq[1][0])

@tornado.gen.coroutine
def connect():
    global current_nodeid
    global nodes_available

    if dashboard_host and dashboard_port:
        print(current_port, "connect dashboard", dashboard_host, "port", dashboard_port)
        tornado.websocket.websocket_connect("ws://%s:%s/control" % (dashboard_host, dashboard_port), callback=control_on_connect, on_message_callback=control_on_message)

    if setting.BOOTSTRAP_BY_PORT_NO:
        if NodeConnector.node_parent:
            return
        if int(current_port) > setting.DASHBOARD_PORT + 1:
            no = int(current_port) - setting.DASHBOARD_PORT
            port = (no >> 1) + setting.DASHBOARD_PORT
            print('Connector', bin(no)[3:])
            NodeConnector(parent_host, port, bin(no)[3:])

        else:
            current_nodeid = ""
            nodes_available.add(tuple([current_host, current_port, current_nodeid]))

    else:
        if parent_host and parent_port:
            NodeConnector(parent_host, parent_port)

        # elif bootstrap_url:
        #     # bootstrap([parent_host, parent_port])
        #     pass

        else:
            current_nodeid = ""
            nodes_available.add(tuple([current_host, current_port, current_nodeid]))

def main():
    global current_name
    global current_host
    global current_port
    global parent_host
    global parent_port
    global dashboard_host
    global dashboard_port
    global bootstrap_url
    global node_sk

    parser = argparse.ArgumentParser(description="node.py --name=<node_name> [--host=127.0.0.1] [--port=8002]")
    parser.add_argument('--name')
    parser.add_argument('--host')
    parser.add_argument('--port')
    parser.add_argument('--parent_host')
    parser.add_argument('--parent_port')
    parser.add_argument('--dashboard_host')
    parser.add_argument('--dashboard_port')
    parser.add_argument('--bootstrap_url')

    args = parser.parse_args()
    if not args.name:
        print('--name reqired')
        sys.exit()
    current_name = args.name
    json_data = {}

    if not os.path.exists('miners'):
        os.makedirs('miners')
    if os.path.exists('miners/%s.json' % current_name):
        with open('miners/%s.json' % current_name) as f:
            json_data = tornado.escape.json_decode(f.read())
            current_host = json_data.get('current_host')
            current_port = json_data.get('current_port')
            parent_host = json_data.get('parent_host')
            parent_port = json_data.get('parent_port')
            dashboard_host = json_data.get('dashboard_host')
            dashboard_port = json_data.get('dashboard_port')

    if args.host:
        current_host = args.host
        json_data['current_host'] = current_host
    if args.port:
        current_port = args.port
        json_data['current_port'] = current_port
    if args.parent_host:
        parent_host = args.parent_host
        json_data['parent_host'] = parent_host
    if args.parent_port:
        parent_port = args.parent_port
        json_data['parent_port'] = parent_port
    if args.dashboard_host:
        dashboard_host = args.dashboard_host
        json_data['dashboard_host'] = dashboard_host
    if args.dashboard_port:
        dashboard_port = args.dashboard_port
        json_data['dashboard_port'] = dashboard_port
    if args.bootstrap_url:
        bootstrap_url = args.bootstrap_url
        # json_data['bootstrap_url'] = bootstrap_url

    with open('miners/%s.json' % current_name, 'w') as f:
        f.write(tornado.escape.json_encode(json_data))

    if setting.BOOTSTRAP_BY_PORT_NO:
        if int(current_port) > setting.DASHBOARD_PORT + 1:
            no = int(current_port) - setting.DASHBOARD_PORT
            parent_port = (no >> 1) + setting.DASHBOARD_PORT

    database.main()

    sk_filename = "miners/%s.key" % current_name
    if os.path.exists(sk_filename):
        f = open(sk_filename, 'rb')
        raw_key = f.read(32)
        f.close()
        node_sk = eth_keys.keys.PrivateKey(raw_key)
    else:
        raw_key = secrets.token_bytes(32)
        f = open(sk_filename, "wb")
        f.write(raw_key)
        f.close()
        node_sk = eth_keys.keys.PrivateKey(raw_key)

    # tornado.ioloop.IOLoop.instance().call_later(int(current_port)-setting.DASHBOARD_PORT, connect)
    tornado.ioloop.IOLoop.instance().add_callback(connect)

if __name__ == '__main__':
    print("run python node.py pls")
