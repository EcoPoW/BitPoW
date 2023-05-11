
import json
import hashlib
import time
import secrets
import base64

import tornado
import nacl.public
# from nacl.public import Box, PrivateKey, PublicKey #x25519-xsalsa20-poly1305

import chain
import database
import tree
import setting


class ChatContactNewHandler(tornado.web.RequestHandler):
    def get(self):
        address = self.get_argument('address')
        db = database.get_conn()
        msg_hash = db.get(b'chain_%s' % address.encode('utf8'))
        msgstate_json = db.get(b'msgstate_%s' % msg_hash)
        # chat_master_pk
        self.finish(msgstate_json)


    def post(self):
        print('------post------')
        address = self.get_argument('address')
        knockdoor_data_encrypted = self.get_argument('knockdoor_data')


class ChatContactRemoveHandler(tornado.web.RequestHandler):
    def get(self):
        print('-----get-------')

    def post(self):
        print('------post------')

                    # (r"/chat_group_new", chat.ChatGroupNewHandler),
                    # (r"/chat_group_join", chat.ChatGroupJoinHandler),
                    # (r"/chat_group_leave", chat.ChatGroupLeaveHandler),
                    # (r"/chat_group_kick", chat.ChatGroupKickHandler),
                    # (r"/chat_msg_new", DashboardHandler),

class ChatGroupNewHandler(tornado.web.RequestHandler):
    def get(self):
        print('-----get-------')

    def post(self):
        print('------post------')


class ChatGroupJoinHandler(tornado.web.RequestHandler):
    def get(self):
        print('-----get-------')

    def post(self):
        print('------post------')


class ChatGroupLeaveHandler(tornado.web.RequestHandler):
    def get(self):
        print('-----get-------')

    def post(self):
        print('------post------')


class ChatGroupKickHandler(tornado.web.RequestHandler):
    def get(self):
        print('-----get-------')

    def post(self):
        print('------post------')

