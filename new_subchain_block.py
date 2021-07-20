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

# from ecdsa import SigningKey, NIST256p
import ecdsa


USER_NO = 10
count = 10
users = {}
transactions = []


def subchain_block():
    # known_addresses_list = list(ControlHandler.known_addresses)
    known_addresses_list = [("127.0.0.1", "8001")]
    addr = random.choice(known_addresses_list)

    print(len(transactions), addr)
    http_client = tornado.httpclient.AsyncHTTPClient()
    # try:
    #     response = yield http_client.fetch("http://%s:%s/new_tx" % tuple(addr), method="POST", body=tornado.escape.json_encode(data))
    # except Exception as e:
    #     print("Error: %s" % e)
    data = transactions.pop()
    http_client.fetch("http://%s:%s/new_subchain_block" % tuple(addr), method="POST", body=tornado.escape.json_encode(data), callback=callback)

def callback(response):
    if len(transactions) == 0:
        tornado.ioloop.IOLoop.instance().stop()
        return
    tornado.ioloop.IOLoop.instance().add_callback(subchain_block)

def main():
    for n in range(USER_NO):
        user_filename = "sk" + str(n)
        user_sk = ecdsa.SigningKey.from_pem(open("users/"+user_filename).read())
        users[n] = user_sk
        print("load key", n)

    for n in range(count):
        # user_nos = set(range(USER_NO))
        # i = random.choice(list(user_nos))
        sender_sk = users[(n*2)%USER_NO]
        sender_vk = sender_sk.get_verifying_key()
        sender = base64.b32encode(sender_vk.to_string()).decode("utf8")
        # sender = str(n*2)

        # j = random.choice(list(user_nos - set([i])))
        receiver_sk = users[(n*2+1)%USER_NO]
        receiver_vk = receiver_sk.get_verifying_key()
        receiver = base64.b32encode(receiver_vk.to_string()).decode("utf8")
        # receiver = str(n*2+1)

        amount = random.randint(1, 20)
        txid = uuid.uuid4().hex
        timestamp = int(time.time())
        transaction = {
            "txid": txid,
            "sender": sender,
            "receiver": receiver,
            "timestamp": timestamp,
            "amount": amount
        }
        # sender_sign = signing.Signer(sender_sk)
        # signature = sender_sk.sign(str(timestamp).encode("utf8"))
        signature = str(n).encode('utf8')
        data = {
            "transaction": transaction,
            "signature": base64.b32encode(signature).decode("utf8")
        }

        # assert sender_vk.verify(signature, str(timestamp).encode("utf8"))
        print("gen subchain block", n)
        transactions.append(data)

    subchain_block()

tornado.ioloop.IOLoop.instance().add_callback(main)
tornado.ioloop.IOLoop.instance().start()
