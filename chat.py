
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



                    # (r"/chat_enable", chat.ChatEnableHandler),
                    # (r"/chat_disable", chat.ChatDisableHandler),

class ChatEnableHandler(tornado.web.RequestHandler):
    def get(self):
        setting.POS_MASTER_ADDRESS
        setting.POS_MASTER_SK

class ChatDisableHandler(tornado.web.RequestHandler):
    def get(self):
        pass


class ChatContactNewHandler(tornado.web.RequestHandler):
    def get(self):
        # print('-----get-------')
        # address = self.get_argument('address')

        # chat_master_pk
        channel_id = secrets.token_bytes(32) # tempchain id
        chat_temp_sk = nacl.public.PrivateKey.generate()
        print('chat_temp_sk', len(chat_temp_sk._private_key))
        chat_temp_pk = chat_temp_sk.public_key

        chat_sk = nacl.public.PrivateKey.generate()
        chat_pk = chat_sk.public_key
        print('chat_pk', len(chat_sk.public_key._public_key))
        tempchain_init_data = {
            'type': 'chat',
            'channel_id': base64.b16encode(channel_id),
            'contacts': [base64.b16encode(chat_pk)],
            'temp_contacts': [base64.b16encode(chat_temp_pk)]
        }

    def post(self):
        print('------post------')
        address = self.get_argument('address')
        data = self.get_argument('data')


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

