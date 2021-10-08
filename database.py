
import os
# import sqlite3
# import uuid

import tree
# import torndb
import rocksdb

conn = None
def get_conn(current_name = None):
    global conn
    if conn:
        return conn

    # if not os.path.exists('%s.db' % current_name):
        # conn = sqlite3.connect('%s.db' % current_name)
        # c = conn.cursor()

        # Create table
        # c.execute('''CREATE TABLE "chain" (
        #         "id"	        INTEGER,
        #         "hash"	        TEXT NOT NULL UNIQUE,
        #         "prev_hash"	    TEXT NOT NULL,
        #         "height"	    INTEGER NOT NULL,
        #         "nonce"	        INTEGER NOT NULL,
        #         "difficulty"	INTEGER NOT NULL,
        #         "identity"	    TEXT NOT NULL,
        #         "timestamp"	    INTEGER NOT NULL,
        #         "data"	        TEXT NOT NULL,
        #         PRIMARY KEY("id" AUTOINCREMENT)
        #     )''')

        # c.execute('''CREATE INDEX "hash" ON "chain" (
	    #         "hash"
        #     )''')

        # c.execute('''CREATE INDEX "prev_hash" ON "chain" (
	    #         "prev_hash"
        #     )''')

        # c.execute('''CREATE INDEX "height" ON "chain" (
	    #         "height"
        #     )''')

        # c.execute('''CREATE TABLE "proof" (
        #         "id"	        INTEGER,
        #         "hash"	        TEXT NOT NULL UNIQUE,
        #         "prev_hash"	    TEXT NOT NULL,
        #         "height"	    INTEGER NOT NULL,
        #         "nonce"	        INTEGER NOT NULL,
        #         "difficulty"	INTEGER NOT NULL,
        #         "identity"	    TEXT NOT NULL,
        #         "timestamp"	    INTEGER NOT NULL,
        #         "data"	        TEXT NOT NULL,
        #         PRIMARY KEY("id" AUTOINCREMENT)
        #     )''')

        # c.execute('''CREATE TABLE "subchains" (
        #         "id"	    INTEGER,
        #         "hash"	    TEXT NOT NULL UNIQUE,
        #         "prev_hash"	TEXT NOT NULL,
        #         "sender"	TEXT NOT NULL,
        #         "receiver"	TEXT NOT NULL,
        #         "height"	INTEGER NOT NULL,
        #         "timestamp"	INTEGER NOT NULL,
        #         "data"	    TEXT NOT NULL,
        #         "signature"	TEXT NOT NULL,
        #         PRIMARY KEY("id" AUTOINCREMENT)
        #     )''')

        # Insert a row of data
        # c.execute("INSERT INTO chain(hash, prev_hash, height, timestamp, data) VALUES (?, ?, 0, CURRENT_TIMESTAMP, '{}')", (uuid.uuid4().hex, uuid.uuid4().hex))

        # Save (commit) the changes
        # conn.commit()

        # We can also close the connection if we are done with it.
        # Just be sure any changes have been committed or they will be lost.
        # conn.close()

    # else:
    #     conn = sqlite3.connect('%s.db' % current_name)

    if not os.path.exists('users'):
        os.makedirs('users')
    conn = rocksdb.DB('miners/%s.db' % current_name, rocksdb.Options(create_if_missing=True))
    return conn


# conn2 = None
# def get_conn2(current_name = None):
#     global conn2
#     if not conn2:
#         conn2 = sqlite3.connect('miners/%s.db' % current_name)
#     return conn2


def main():
    if not tree.current_name:
        return
    get_conn(tree.current_name)
