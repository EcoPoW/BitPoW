from __future__ import print_function

import math
import time
import uuid
import hashlib
import copy
import base64
import urllib.request

import tornado.web
import tornado.websocket
import tornado.ioloop
import tornado.httpclient
import tornado.gen
import tornado.escape

import setting
import tree
import node
# import leader
import database


frozen_block_hash = '0'*64
frozen_chain = ['0'*64]
frozen_nodes_in_chain = {}
highest_block_hash = None
recent_longest = []
nodes_in_chain = {}
# def longest_chain2(from_hash = '0'*64):
#     roots = database.get_conn().query("SELECT * FROM chain"+tree.current_port+" WHERE prev_hash = %s ORDER BY nonce", from_hash)

#     chains = []
#     prev_hashs = []
#     for root in roots:
#         # chains.append([root.hash])
#         chains.append([root])
#         prev_hashs.append(root.hash)

#     t0 = time.time()
#     n = 0
#     while True:
#         if prev_hashs:
#             prev_hash = prev_hashs.pop(0)
#         else:
#             break

#         leaves = database.get_conn().query("SELECT * FROM chain"+tree.current_port+" WHERE prev_hash = %s ORDER BY nonce", prev_hash)
#         n += 1
#         if len(leaves) > 0:
#             if leaves[0]['height'] % 1000 == 0:
#                 print('longest height', leaves[0]['height'])
#             for leaf in leaves:
#                 for c in chains:
#                     if c[-1].hash == prev_hash:
#                         chain = copy.copy(c)
#                         # chain.append(leaf.hash)
#                         chain.append(leaf)
#                         chains.append(chain)
#                         break
#                 if leaf.hash not in prev_hashs and leaf.hash:
#                     prev_hashs.append(leaf.hash)
#     t1 = time.time()
#     # print(tree.current_port, "query time", t1-t0, n)

#     longest = []
#     for i in chains:
#         # print(i)
#         if not longest:
#             longest = i
#         if len(longest) < len(i):
#             longest = i
#     return longest

# def longest_chain(from_hash = '0'*64):
#     roots = database.get_conn().query("SELECT * FROM chain"+tree.current_port+" WHERE prev_hash = %s", from_hash)
#     if not roots:
#         return []

#     assert([root for root in roots if root['height'] == roots[0]['height']])
#     height = roots[0]['height']

#     # return [h['height'] for h in heights]
#     chains = [[root] for root in roots]

#     t0 = time.time()
#     n = height
#     while True:
#         # print(n, height)
#         if n == height:
#             heights = database.get_conn().query("SELECT * FROM chain"+tree.current_port+" WHERE height > %s AND height <= %s ORDER BY height", height, height+10)
#             # print('>>>', [i['height'] for i in heights])
#             height += 10
#         n += 1

#         new_chains = []
#         for chain in chains:
#             # print('...', [i['height'] for i in chain])
#             leaves = [i for i in heights if i['height'] == n and i['prev_hash'] == chain[-1]['hash']]
#             # print([i['height'] for i in leaves])

#             if len(leaves) > 0:
#                 for leaf in leaves:
#                     new_chain = copy.copy(chain)
#                     new_chain.append(leaf)
#                     new_chains.append(new_chain)

#         if new_chains:
#             chains = new_chains
#         else:
#             break


#     t1 = time.time()
#     print(tree.current_port, "query time", t1-t0, n)
#     return chains[0]

#     # longest = []
#     # for i in chains:
#     #     # print(i)
#     #     if not longest:
#     #         longest = i
#     #     if len(longest) < len(i):
#     #         longest = i
#     # return longest


def longest_chain(from_hash = '0'*64):
    conn = database.get_conn2()
    c = conn.cursor()
    c.execute("SELECT * FROM chain WHERE prev_hash = ?", (from_hash,))
    roots = c.fetchall()

    chains = []
    prev_hashs = []
    for root in roots:
        # chains.append([root.hash])
        chains.append([root])
        # print(root)
        block_hash = root[1]
        prev_hashs.append(block_hash)

    t0 = time.time()
    n = 0
    while True:
        if prev_hashs:
            prev_hash = prev_hashs.pop(0)
        else:
            break

        c.execute("SELECT * FROM chain WHERE prev_hash = ?", (prev_hash,))
        leaves = c.fetchall()
        n += 1
        if len(leaves) > 0:
            block_height = leaves[0][3]
            if block_height % 1000 == 0:
                print('longest height', block_height)
            for leaf in leaves:
                for chain in chains:
                    prev_block = chain[-1]
                    prev_block_hash = prev_block[1]
                    # print(prev_block_hash)
                    if prev_block_hash == prev_hash:
                        forking_chain = copy.copy(chain)
                        # chain.append(leaf.hash)
                        chain.append(leaf)
                        chains.append(forking_chain)
                        break
                leaf_hash = leaf[1]
                if leaf_hash not in prev_hashs and leaf_hash:
                    prev_hashs.append(leaf_hash)
    t1 = time.time()
    # print(tree.current_port, "query time", t1-t0, n)

    longest = []
    for i in chains:
        # print(i)
        if not longest:
            longest = i
        if len(longest) < len(i):
            longest = i
    return longest


messages_out = []
def looping():
    global messages_out
    global recent_longest

    while messages_out:
        message = messages_out.pop(0)
        tree.forward(message)

    # if recent_longest:
    #     leaders = [i for i in recent_longest if i['timestamp'] < time.time()-setting.MAX_MESSAGE_DELAY_SECONDS and i['timestamp'] > time.time()-setting.MAX_MESSAGE_DELAY_SECONDS - setting.BLOCK_INTERVAL_SECONDS*20][-setting.LEADERS_NUM:]
    #     # print(leaders)
    #     leader.update(leaders)

    tornado.ioloop.IOLoop.instance().call_later(1, looping)

nodes_to_fetch = []
highest_block_height = 0
@tornado.gen.coroutine
def new_block(seq):
    # global frozen_block_hash
    global nodes_to_fetch
    global recent_longest
    global worker_thread_mining
    global highest_block_height

    msg_header, block_hash, prev_hash, height, nonce, difficulty, identity, data, timestamp, msg_id = seq
    conn = database.get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO chain (hash, prev_hash, height, nonce, difficulty, identity, timestamp, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (block_hash, prev_hash, height, nonce, difficulty, identity, timestamp, tornado.escape.json_encode(data)))
        conn.commit()
    except Exception as e:
        print("new_block Error: %s" % e)

    # if prev_hash != '0'*64:
    #     prev_block = database.connection.get("SELECT * FROM chain"+tree.current_port+" WHERE hash = %s", prev_hash)
    #     if not prev_block:
    #         no, pk = identity.split(":")
    #         if int(no) not in nodes_to_fetch:
    #             nodes_to_fetch.append(int(no))
    #         worker_thread_mining = False

    print(highest_block_height, height, identity)
    if highest_block_height + 1 < height:
        no, pk = identity.split(":")
        if int(no) not in nodes_to_fetch:
            nodes_to_fetch.append(int(no))
        worker_thread_mining = False
    elif highest_block_height + 1 == height:
        highest_block_height = height

class GetHighestBlockHandler(tornado.web.RequestHandler):
    def get(self):
        global highest_block_hash
        self.finish({"hash": highest_block_hash})

class GetBlockHandler(tornado.web.RequestHandler):
    def get(self):
        block_hash = self.get_argument("hash")
        block = database.connection.get("SELECT * FROM chain"+tree.current_port+" WHERE hash = %s", block_hash)
        self.finish({"block": block})


def fetch_chain(nodeid):
    print(tree.current_nodeid, 'fetch chain', nodeid)
    host, port = tree.current_host, tree.current_port
    prev_nodeid = None
    while True:
        try:
            response = urllib.request.urlopen("http://%s:%s/get_node?nodeid=%s" % (host, port, nodeid))
        except:
            break
        result = tornado.escape.json_decode(response.read())
        host, port = result['address']
        if result['nodeid'] == result['current_nodeid']:
            break
        if prev_nodeid == result['current_nodeid']:
            break
        prev_nodeid = result['current_nodeid']
        print('result >>>>>', nodeid, result)

    try:
        response = urllib.request.urlopen("http://%s:%s/get_highest_block" % (host, port))
    except:
        return
    result = tornado.escape.json_decode(response.read())
    block_hash = result['hash']
    if not block_hash:
        return
    print("get highest block", block_hash)
    while block_hash != '0'*64:
        block = database.get_conn2().get("SELECT * FROM chain"+tree.current_port+" WHERE hash = %s", block_hash)
        if block:
            if block['height'] % 1000 == 0:
                print('block height', block['height'])
            block_hash = block['prev_hash']
            continue
        try:
            response = urllib.request.urlopen("http://%s:%s/get_block?hash=%s" % (host, port, block_hash))
        except:
            continue
        result = tornado.escape.json_decode(response.read())
        block = result["block"]
        # if block['height'] % 1000 == 0:
        print("fetch block", block['height'])
        block_hash = block['prev_hash']
        try:
            database.get_conn2().execute("INSERT INTO chain"+tree.current_port+" (hash, prev_hash, height, nonce, difficulty, identity, timestamp, data) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                block["hash"], block["prev_hash"], block["height"], block["nonce"], block["difficulty"], block["identity"], block["timestamp"], block["data"])
        except Exception as e:
            print("fetch_chain Error: %s" % e)

nonce = 0
def mining():
    global nonce
    global frozen_block_hash
    global frozen_chain
    global frozen_nodes_in_chain
    global recent_longest
    global nodes_in_chain
    global highest_block_hash
    global highest_block_height
    global messages_out

    longest = longest_chain(frozen_block_hash)
    if longest:
        highest_block_hash = longest[-1][1]#.hash
        if highest_block_height < longest[-1][3]:#.height
            highest_block_height = longest[-1][3]#.height

    if len(longest) > setting.FROZEN_BLOCK_NO:
        frozen_block_hash = longest[-setting.FROZEN_BLOCK_NO].prev_hash
        frozen_longest = longest[:-setting.FROZEN_BLOCK_NO]
        recent_longest = longest[-setting.FROZEN_BLOCK_NO:]
    else:
        frozen_longest = []
        recent_longest = longest

    for i in frozen_longest:
        print("frozen longest", i.height)
        data = tornado.escape.json_decode(i.data)
        frozen_nodes_in_chain.update(data.get("nodes", {}))
        if i.hash not in frozen_chain:
            frozen_chain.append(i.hash)

    nodes_in_chain = copy.copy(frozen_nodes_in_chain)
    for i in recent_longest:
        data = tornado.escape.json_decode(i[8])#.data
        # for j in data.get("nodes", {}):
        #     print("recent longest", i.height, j, data["nodes"][j])
        nodes_in_chain.update(data.get("nodes", {}))

    # if tree.current_nodeid not in nodes_in_chain and tree.parent_node_id_msg:
    #     tree.forward(tree.parent_node_id_msg)
    #     print(tree.current_port, 'parent_node_id_msg', tree.parent_node_id_msg)

    if len(recent_longest) > setting.BLOCK_DIFFICULTY_CYCLE:
        height_in_cycle = recent_longest[-1][3] % setting.BLOCK_DIFFICULTY_CYCLE #.height
        timecost = recent_longest[-1-height_in_cycle][7] - recent_longest[-height_in_cycle-setting.BLOCK_DIFFICULTY_CYCLE][7]
        difficulty = 2**248 * timecost / (setting.BLOCK_INTERVAL_SECONDS * setting.BLOCK_DIFFICULTY_CYCLE)#.timestamp
    else:
        difficulty = 2**248

    now = int(time.time())
    last_synctime = now - now % setting.NETWORK_SPREADING_SECONDS - setting.NETWORK_SPREADING_SECONDS
    nodes_to_update = {}
    for nodeid in tree.nodes_pool:
        if tree.nodes_pool[nodeid][1] < last_synctime:
            if nodeid not in nodes_in_chain or nodes_in_chain[nodeid][1] < tree.nodes_pool[nodeid][1]:
                # print("nodes_to_update", nodeid, nodes_in_chain[nodeid][1], tree.nodes_pool[nodeid][1], last_synctime)
                nodes_to_update[nodeid] = tree.nodes_pool[nodeid]

    # nodes_in_chain.update(tree.nodes_pool)
    # tree.nodes_pool = nodes_in_chain
    # print(tree.nodes_pool)
    # print(nodes_to_update)

    # print(frozen_block_hash, longest)
    nodeno = str(tree.nodeid2no(tree.current_nodeid))
    pk = base64.b32encode(tree.node_sk.get_verifying_key().to_string()).decode("utf8")
    if longest:
        prev_hash = longest[-1][1]#.hash
        height = longest[-1][3]#.height
        identity = longest[-1][6]#.identity
        data = tornado.escape.json_decode(longest[-1][8])#.data
        # print(tree.dashboard_port, "new difficulty", new_difficulty, "height", height)

        # print("%s:%s" % (nodeno, pk))
        # leaders = [i for i in longest if i['timestamp'] < time.time()-setting.MAX_MESSAGE_DELAY_SECONDS and i['timestamp'] > time.time()-setting.MAX_MESSAGE_DELAY_SECONDS - setting.BLOCK_INTERVAL_SECONDS*20][-setting.LEADERS_NUM:]
        # if "%s:%s" % (nodeno, pk) in [i.identity for i in leaders]:
        #     # tornado.ioloop.IOLoop.instance().call_later(1, mining)
        #     # print([i.identity for i in leaders])
        #     return

    else:
        prev_hash, height, data, identity = '0'*64, 0, {}, ":"
    new_difficulty = int(math.log(difficulty, 2))

    # data = {"nodes": {k:list(v) for k, v in tree.nodes_pool.items()}}
    data["nodes"] = nodes_to_update
    data_json = tornado.escape.json_encode(data)

    # new_identity = "%s@%s:%s" % (tree.current_nodeid, tree.current_host, tree.current_port)
    new_identity = "%s:%s" % (nodeno, pk)
    new_timestamp = time.time()
    for i in range(100):
        block_hash = hashlib.sha256((prev_hash + data_json + str(new_timestamp) + str(difficulty) + new_identity + str(nonce)).encode('utf8')).hexdigest()
        if int(block_hash, 16) < difficulty:
            if longest:
                print(tree.current_port, 'height', height, 'nodeid', tree.current_nodeid, 'nonce_init', tree.nodeid2no(tree.current_nodeid), 'timecost', longest[-1][7] - longest[0][7])#.timestamp

            message = ["NEW_CHAIN_BLOCK", block_hash, prev_hash, height+1, nonce, new_difficulty, new_identity, data, new_timestamp, uuid.uuid4().hex]
            messages_out.append(message)
            # print(tree.current_port, "mining", nonce, block_hash)
            nonce = 0
            break

        nonce += 1

def validate():
    global highest_block_hash
    global highest_block_height
    global nodes_to_fetch
    global frozen_nodes_in_chain
    global frozen_chain
    global frozen_block_hash
    global worker_thread_mining

    c = 0
    for no in nodes_to_fetch:
        c += 1
        # no = nodes_to_fetch[0]
        nodeid = tree.nodeno2id(no)
        fetch_chain(nodeid)

    longest = longest_chain(frozen_block_hash)
    print(longest)
    if len(longest) >= setting.FROZEN_BLOCK_NO:
        frozen_block_hash = longest[-setting.FROZEN_BLOCK_NO].prev_hash
        frozen_longest = longest[:-setting.FROZEN_BLOCK_NO]
    #     recent_longest = longest[-setting.FROZEN_BLOCK_NO:]
    else:
        frozen_longest = []
    #     recent_longest = longest

    if longest:
        highest_block_hash = longest[-1][1] #.hash
        if highest_block_height < longest[-1][3]: #.height
            highest_block_height = longest[-1][3] #.height
    else:
        highest_block_hash = '0'*64

    for i in frozen_longest:
        if i[3] % 1000 == 0: #.height
            print("frozen longest reload", i[3])#.height
        data = tornado.escape.json_decode(i[8]) #.data
        frozen_nodes_in_chain.update(data.get("nodes", {}))
        if i[1] not in frozen_chain: #.hash
            frozen_chain.append(i[1]) #.hash

    for i in range(c):
        nodes_to_fetch.pop(0)
    if not nodes_to_fetch:
        worker_thread_mining = True


worker_thread_mining = False
def worker_thread():
    global frozen_block_hash
    global frozen_chain
    global frozen_nodes_in_chain
    # global recent_longest
    global nodes_in_chain
    global worker_thread_mining

    database.get_conn2(tree.current_name)

    while True:
        time.sleep(2)
        if worker_thread_mining and setting.MINING:
            # print('chain mining')
            mining()
            continue

        if tree.current_nodeid is None:
            continue

        # print('chain validation')
        # if tree.current_nodeid:
        #     fetch_chain(tree.current_nodeid[:-1])
        validate()

    # mining_task = tornado.ioloop.PeriodicCallback(mining, 1000) # , jitter=0.5
    # mining_task.start()
    # print(tree.current_port, "miner")


# @tornado.gen.coroutine
# def main():
#     tornado.ioloop.IOLoop.instance().call_later(1, looping)

if __name__ == '__main__':
    print("run python node.py pls")
    tree.current_port = "8001"
    # longest_chain2()
    longest_chain()
