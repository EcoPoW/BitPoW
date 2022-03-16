from __future__ import print_function
from inspect import signature

import os
import time
import hashlib
import uuid
import threading
import tracemalloc
# import subprocess
# import base64

import tornado.web
import tornado.ioloop
import tornado.options
import tornado.httpserver
import tornado.gen
import tornado.escape
# import tornado.httpclient
# import tornado.websocket

import eth_keys
import eth_utils

tracemalloc.start()

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/recover_public_key_from_msg_hash", RecoverPublicKeyFromMsgHashHandler),
        ]
        settings = {"debug":True}

        tornado.web.Application.__init__(self, handlers, **settings)

class RecoverPublicKeyFromMsgHashHandler(tornado.web.RequestHandler):
    def get(self):
        signature = self.get_argument('signature', None)
        block_hash = self.get_argument('hash', None)

        sig = eth_keys.keys.Signature(eth_utils.hexadecimal.decode_hex(signature))
        pk = sig.recover_public_key_from_msg_hash(eth_utils.hexadecimal.decode_hex(block_hash))
        print('sig', pk)
        # print('id', pk.to_checksum_address(), sender)

def main():
    server = Application()
    server.listen(7001, '127.0.0.1')
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()

