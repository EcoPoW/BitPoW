from __future__ import print_function

import os
import subprocess
import time
import socket
import argparse
import random
import uuid
import base64
import hashlib
import urllib

import tornado.web
import tornado.websocket
import tornado.ioloop
import tornado.options
import tornado.httpserver
import tornado.gen
import tornado.escape

from ecdsa import SigningKey, NIST256p
import setting
# from umbral import pre, keys, signing
# import umbral.config

incremental_port = setting.DASHBOARD_PORT

@tornado.gen.coroutine
def get_node(target):
    known_addresses_list = list(ControlHandler.known_addresses)
    addr = random.choice(known_addresses_list)
    http_client = tornado.httpclient.AsyncHTTPClient()
    while True:
        url = "http://%s:%s/get_node?nodeid=%s" % (tuple(addr)+(target,))
        try:
            response = yield http_client.fetch(url)#, method="POST", body=tornado.escape.json_encode(data)
        except Exception as e:
            print("Error: %s" % e)
        print(addr, response.body)
        res = tornado.escape.json_decode(response.body)
        if res["nodeid"] == res["current_nodeid"]:
            break
        addr = res["address"][0]
    yield addr, res["nodeid"]
    return

class Application(tornado.web.Application):
    def __init__(self):
        settings = {
            "debug":True,
            "static_path": os.path.join(os.path.dirname(__file__), "static"),
        }
        handlers = [(r"/control", ControlHandler),
                    (r"/new_node", NewNodeHandler),
                    (r"/new_tx", NewTxHandler),
                    (r"/new_msg", NewMsgHandler),
                    (r"/dashboard", DashboardHandler),
                    (r"/get_user", GetUserHandler),
                    (r"/new_user", NewUserHandler),
                    (r"/new_file", NewFileHandler),
                    (r"/visualize", VisualizeHandler),
                    (r"/visualize_data", VisualizeDataHandler),
                    (r"/static/(.*)", tornado.web.StaticFileHandler, dict(path=settings['static_path'])),
                    ]

        tornado.web.Application.__init__(self, handlers, **settings)

class NewNodeHandler(tornado.web.RequestHandler):
    # @tornado.gen.coroutine
    def get(self):
        global incremental_port
        self.count = int(self.get_argument("n", "1"))
        for i in range(self.count):
            incremental_port += 1
            subprocess.Popen([setting.PYTHON_EXECUTABLE, "node.py", "--host=%s"%dashboard_host, "--port=%s"%incremental_port, "--dashboard_host=%s"%dashboard_host, "--dashboard_port=%s"%dashboard_port], shell=False)
            self.write("new node %s\n" % incremental_port)


class NewMsgHandler(tornado.web.RequestHandler):
    @tornado.gen.coroutine
    def get(self):
        msg = self.get_argument("msg")
        http_client = tornado.httpclient.AsyncHTTPClient()

        sender_filename = "pk0"
        sender_sk = SigningKey.from_pem(open("data/pk/"+sender_filename).read())
        sender_vk = sender_sk.get_verifying_key()
        sender = base64.b32encode(sender_vk.to_string()).decode("utf8")

        j = random.randint(1,9)
        receiver_filename = "pk%s" % j
        receiver_sk = SigningKey.from_pem(open("data/pk/"+receiver_filename).read())
        receiver_vk = receiver_sk.get_verifying_key()
        receiver = base64.b32encode(receiver_vk.to_string()).decode("utf8")

        msgid = uuid.uuid4().hex
        # amount = random.randint(1, 10)
        timestamp = int(time.time())
        message = {
            "msgid": msgid,
            "sender": sender,
            "receiver": receiver,
            "timestamp": timestamp,
            "amount": 0,
            "content": msg
        }
        signature = sender_sk.sign(str(timestamp).encode("utf8"))
        data = {
            "message": message,
            "signature": base64.b32encode(signature).decode("utf8")
        }

        print("gen msg", msgid)
        known_addresses_list = list(ControlHandler.known_addresses)
        addr = ["127.0.0.1", str(setting.DASHBOARD_PORT+1)]
        response = yield http_client.fetch("http://%s:%s/new_msg" % tuple(addr), method="POST", body=tornado.escape.json_encode(data))

        self.finish({"msgid": msgid})


class GetMsgHandler(tornado.web.RequestHandler):
    @tornado.gen.coroutine
    def get(self):
        # tx = tornado.escape.json_decode(self.request.body)
        # tree.forward(["NEW_TX", tx, time.time(), uuid.uuid4().hex])
        self.finish({"msg": []})


class NewTxHandler(tornado.web.RequestHandler):
    @tornado.gen.coroutine
    def get(self):
        USER_NO = 10
        self.count = int(self.get_argument("n", "1"))
        self.users = {}
        for n in range(USER_NO):
            user_filename = "pk" + str(n)
            user_sk = SigningKey.from_pem(open("data/pk/"+user_filename).read())
            self.users[n] = user_sk
            print("load key", n)

        # self.transactions = []
        http_client = tornado.httpclient.AsyncHTTPClient()
        for n in range(self.count):
            user_nos = set(range(USER_NO))
            i = random.choice(list(user_nos))
            sender_sk = self.users[i]
            sender_vk = sender_sk.get_verifying_key()
            sender = base64.b32encode(sender_vk.to_string()).decode("utf8")

            j = random.choice(list(user_nos - set([i])))
            receiver_sk = self.users[j]
            receiver_vk = receiver_sk.get_verifying_key()
            receiver = base64.b32encode(receiver_vk.to_string()).decode("utf8")

            amount = random.randint(1, 10)
            txid = uuid.uuid4().hex
            timestamp = int(time.time())
            transaction = {
                "txid": txid,
                "sender": sender,
                "receiver": receiver,
                "timestamp": timestamp,
                "amount": amount
            }
            signature = sender_sk.sign(str(timestamp).encode("utf8"))
            data = {
                "transaction": transaction,
                "signature": base64.b32encode(signature).decode("utf8")
            }

            print("gen tx", n, txid)
            known_addresses_list = list(ControlHandler.known_addresses)
            addr = random.choice(known_addresses_list)

            # print(len(self.transactions), addr)
            # try:
            #     response = yield http_client.fetch("http://%s:%s/new_tx" % tuple(addr), method="POST", body=tornado.escape.json_encode(data))
            # except Exception as e:
            #     print("Error: %s" % e)
            # data = self.transactions.pop()
            response = yield http_client.fetch("http://%s:%s/new_tx" % tuple(addr), method="POST", body=tornado.escape.json_encode(data))
        self.finish()


class GetUserHandler(tornado.web.RequestHandler):
    @tornado.gen.coroutine
    def get(self):
        sk_filename = "pk1"
        sk = keys.UmbralPrivateKey.from_bytes(bytes.fromhex(open("data/pk/"+sk_filename).read()))
        vk = sk.get_pubkey()
        user_id = vk.to_bytes().hex()
        # sender_binary = bin(int(vk.to_bytes().hex(), 16))#[2:].zfill(768)
        timestamp = time.time()
        sk_sign = signing.Signer(sk)
        signature = sk_sign(str(timestamp).encode("utf8"))
        assert signature.verify(str(timestamp).encode("utf8"), vk)

        known_addresses_list = list(ControlHandler.known_addresses)
        addr = random.choice(known_addresses_list)
        http_client = tornado.httpclient.AsyncHTTPClient()
        print(len(vk.to_bytes().hex()), vk.to_bytes().hex())
        # print(len(bin(int(vk.to_bytes().hex(), 16))), bin(int(vk.to_bytes().hex(), 16)))
        print(len(bytes(signature).hex()), bytes(signature).hex())
        url = "http://%s:%s/user?user_id=%s&timestamp=%s&signature=%s" % (tuple(addr)+(user_id, str(timestamp), bytes(signature).hex()))
        # print(url)
        try:
            response = yield http_client.fetch(url)#, method="POST", body=tornado.escape.json_encode(data)
        except Exception as e:
            print("GetUserHandler Error: %s" % e)

        self.finish(tornado.escape.json_decode(response.body))

class NewUserHandler(tornado.web.RequestHandler):
    @tornado.gen.coroutine
    def get(self):
        sk_filename = "pk1"
        sk = keys.UmbralPrivateKey.gen_key()
        open("data/pk/"+sk_filename, "w").write(sk.to_bytes().hex())
        vk = sk.get_pubkey()
        user_id = vk.to_bytes().hex()
        timestamp = str(time.time())
        sk_sign = signing.Signer(sk)
        signature = sk_sign(timestamp.encode("utf8"))

        content = b"{}"
        ciphertext, capsule = pre.encrypt(vk, content)
        folder_size = "0"
        block_size = len(ciphertext)
        folder_hash = hashlib.sha1(ciphertext).hexdigest()
        folder_hash_binary = bin(int(folder_hash, 16))[2:].zfill(32*4)
        addr, nodeid = yield get_node(folder_hash_binary)
        print("ciphertext", len(ciphertext), "capsule", capsule.to_bytes().hex())

        http_client = tornado.httpclient.AsyncHTTPClient()
        url = "http://%s:%s/user?user_id=%s&folder_hash=%s&block_size=%s&folder_size=%s&nodeid=%s&capsule=%s&timestamp=%s&signature=%s" \
                % (tuple(addr)+(user_id, folder_hash, block_size, folder_size, nodeid, capsule.to_bytes().hex(), timestamp, bytes(signature).hex()))
        try:
            response = yield http_client.fetch(url, method="POST", body=ciphertext)
        except Exception as e:
            print("NewUserHandler Error: %s" % e)

        self.finish({"user_id":user_id})

class NewFileHandler(tornado.web.RequestHandler):
    @tornado.gen.coroutine
    def get(self):
        sk_filename = "pk1"
        sk = keys.UmbralPrivateKey.from_bytes(bytes.fromhex(open("data/pk/"+sk_filename).read()))
        vk = sk.get_pubkey()
        user_id = vk.to_bytes().hex()
        http_client = tornado.httpclient.AsyncHTTPClient()

        # get root tree hash from blockchain, from random node
        timestamp = time.time()
        sk_sign = signing.Signer(sk)
        signature = sk_sign(str(timestamp).encode("utf8"))
        assert signature.verify(str(timestamp).encode("utf8"), vk)

        known_addresses_list = list(ControlHandler.known_addresses)
        addr = random.choice(known_addresses_list)
        # print(len(vk.to_bytes().hex()), vk.to_bytes().hex())
        # print(len(bytes(signature).hex()), bytes(signature).hex())
        url = "http://%s:%s/user?user_id=%s&timestamp=%s&signature=%s" % (tuple(addr)+(user_id, str(timestamp), bytes(signature).hex()))
        try:
            response = yield http_client.fetch(url)#, method="POST", body=tornado.escape.json_encode(data)
            user = tornado.escape.json_decode(response.body)
            # print(user)
            nodeid = user["nodeid"]
            folder_hash = user["folder_hash"]
        except Exception as e:
            print("NewFileHandler Error: %s" % e)

        # get content object and capsule from the node
        timestamp = time.time()
        sk_sign = signing.Signer(sk)
        signature = sk_sign((str(folder_hash)+str(timestamp)).encode("utf8"))
        assert signature.verify((str(folder_hash)+str(timestamp)).encode("utf8"), vk)

        addr, _ = yield get_node(nodeid)
        print(_, nodeid)
        url = "http://%s:%s/object?hash=%s&user_id=%s&timestamp=%s&signature=%s" % (tuple(addr)+(folder_hash, user_id, str(timestamp), bytes(signature).hex()))
        response = yield http_client.fetch(url)
        ciphertext = response.body

        url = "http://%s:%s/capsule?hash=%s&user_id=%s&timestamp=%s&signature=%s" % (tuple(addr)+(folder_hash, user_id, str(timestamp), bytes(signature).hex()))
        response = yield http_client.fetch(url)
        capsule = response.body

        # decode
        print(ciphertext, capsule)
        cleartext = pre.decrypt(ciphertext=ciphertext,
                                capsule=pre.Capsule.from_bytes(capsule, umbral.config.default_params()),
                                decrypting_key=sk)

        # put file
        content = open("data/pk/"+sk_filename, "rb").read()
        ciphertext, capsule = pre.encrypt(vk, content)
        print(len(ciphertext), capsule.to_bytes())
        sha1 = hashlib.sha1(ciphertext).hexdigest()
        sha1_binary = bin(int(sha1, 16))[2:].zfill(32*4)
        print(sha1_binary, len(sha1_binary), sha1, 16)
        addr, nodeid = yield get_node(sha1_binary)

        timestamp = time.time()
        sk_sign = signing.Signer(sk)
        signature = sk_sign((str(sha1)+str(timestamp)).encode("utf8"))
        assert signature.verify((str(sha1)+str(timestamp)).encode("utf8"), vk)

        url = "http://%s:%s/object?hash=%s&user_id=%s&timestamp=%s&signature=%s" % (tuple(addr)+(sha1, user_id, str(timestamp), bytes(signature).hex()))
        http_client = tornado.httpclient.AsyncHTTPClient()
        response = yield http_client.fetch(url, method="POST", body=ciphertext)
        print(len(ciphertext), ciphertext)

        # update
        data = tornado.escape.json_decode(cleartext)
        data["filename"] = [sha1, len(ciphertext), nodeid, time.time()]

        # encode
        content = tornado.escape.json_encode(data).encode("utf8")
        ciphertext, capsule = pre.encrypt(vk, content)
        folder_size = str(len(ciphertext))
        block_size = len(ciphertext)
        folder_hash = hashlib.sha1(ciphertext).hexdigest()
        folder_hash_binary = bin(int(folder_hash, 16))[2:].zfill(32*4)
        addr, nodeid = yield get_node(folder_hash_binary)
        print("ciphertext", len(ciphertext), "capsule", capsule.to_bytes().hex())

        # put
        timestamp = time.time()
        sk_sign = signing.Signer(sk)
        signature = sk_sign(str(timestamp).encode("utf8"))
        assert signature.verify(str(timestamp).encode("utf8"), vk)

        url = "http://%s:%s/user?user_id=%s&folder_hash=%s&block_size=%s&folder_size=%s&nodeid=%s&capsule=%s&timestamp=%s&signature=%s" \
                % (tuple(addr)+(user_id, folder_hash, block_size, folder_size, nodeid, capsule.to_bytes().hex(), timestamp, bytes(signature).hex()))
        try:
            response = yield http_client.fetch(url, method="POST", body=ciphertext)
        except Exception as e:
            print("Error: %s" % e)


class DashboardHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("")
        self.finish()

class ControlHandler(tornado.websocket.WebSocketHandler):
    known_addresses = {}
    # bootstrap_msg_cache = {}

    # def data_received(self, chunk):
    #     print("data received")

    def check_origin(self, origin):
        return True

    def open(self):
        print("control: node connected")
        # print("Clients", len(ControlHandler.known_addresses))
        self.addr = None

    def on_close(self):
        print("control: node disconnected")
        if self.addr in ControlHandler.known_addresses:
            del ControlHandler.known_addresses[self.addr]

    # def send_to_client(self, msg):
    #     print("send message: %s" % msg)
    #     self.write_message(msg)

    @tornado.gen.coroutine
    def on_message(self, msg):
        seq = tornado.escape.json_decode(msg)
        print("control on message", seq)
        if seq[0] == "ADDRESS":
            self.addr = tuple(seq[1:3])
            # print(self.addr)
            known_addresses_list = list(ControlHandler.known_addresses)
            random.shuffle(known_addresses_list)
            # known_addresses_list.sort(key=lambda l:int(l[1]))
            bootstrap_msg = tornado.escape.json_encode(["BOOTSTRAP_ADDRESS", known_addresses_list[:3]])
            # if self.addr in self.bootstrap_msg_cache:
            #     bootstrap_msg = self.bootstrap_msg_cache[self.addr]
            # else:
            #     self.bootstrap_msg_cache[self.addr] = bootstrap_msg
            self.write_message(bootstrap_msg)
            ControlHandler.known_addresses[self.addr] = self
            # print(ControlHandler.known_addresses)
        # elif seq[0] == "ADDRESS2":
        #     pass

        for w in VisualizeDataHandler.waiters:
            w.write_message(msg)


class VisualizeHandler(tornado.web.RequestHandler):
    def get(self):
        # global control_node
        self.messages = VisualizeDataHandler.cache
        self.render("index.html")


class VisualizeDataHandler(tornado.websocket.WebSocketHandler):
    waiters = set()
    cache = []
    cache_size = 200

    def open(self):
        # print ("new client opened")
        VisualizeDataHandler.waiters.add(self)

    def on_close(self):
        VisualizeDataHandler.waiters.remove(self)

    @classmethod
    def update_cache(cls, msg):
        cls.cache.append(msg)
        if len(cls.cache) > cls.cache_size:
            cls.cache = cls.cache[-cls.cache_size:]

    @classmethod
    def send_updates(cls, msg):
        print("sending message to waiters", len(cls.waiters))
        # logging.info("sending message to %d waiters", len(cls.waiters))
        for waiter in cls.waiters:
            try:
                waiter.write_message(msg)
            except:
                logging.error("Error sending message", exc_info=True)

    def on_message(self, message):
        # logging.info("got message %r", message)
        print("got message ", message)
        # self.write("<br>current_nodeid: %s <br>" % message)
        VisualizeDataHandler.send_updates(message)

# def boot():
#     # os.system("curl 127.0.0.1:8000/new_node?n=9")
#     http_client = tornado.httpclient.AsyncHTTPClient()
#     http_client.fetch("http://127.0.0.1:8000/new_node?n=9", method="GET")

def main():
    global dashboard_host
    global dashboard_port

    parser = argparse.ArgumentParser(description="control description")
    parser.add_argument('--dashboard_host', default="127.0.0.1")
    parser.add_argument('--dashboard_port', default=setting.DASHBOARD_PORT)

    args = parser.parse_args()
    dashboard_host = args.dashboard_host
    dashboard_port = args.dashboard_port

    server = Application()
    server.listen(dashboard_port)
    # tornado.ioloop.IOLoop.instance().call_later(2, boot)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
