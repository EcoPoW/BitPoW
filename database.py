
import os
import sqlite3
import uuid

# import torndb
import tree

conn = None
def get_conn(current_name = None):
    global conn
    if conn:
        return conn

    if not os.path.exists('%s.db' % current_name):
        conn = sqlite3.connect('%s.db' % current_name)
        c = conn.cursor()

        # Create table
        c.execute('''CREATE TABLE "chain" (
                "id"	    INTEGER,
                "hash"	    TEXT NOT NULL,
                "prev_hash"	TEXT NOT NULL,
                "height"	INTEGER NOT NULL,
                "nonce"	    INTEGER NOT NULL,
                "difficulty"	INTEGER NOT NULL,
                "identity"	TEXT NOT NULL,
                "timestamp"	INTEGER NOT NULL,
                "data"	TEXT NOT NULL,
                PRIMARY KEY("id" AUTOINCREMENT)
            )''')

        c.execute('''CREATE TABLE "subchains" (
                "id"	INTEGER,
                "sender"	TEXT NOT NULL,
                "receiver"	TEXT NOT NULL,
                "hash"	TEXT NOT NULL,
                "prev_hash"	TEXT NOT NULL,
                "height"	INTEGER NOT NULL,
                "timestamp"	INTEGER NOT NULL,
                "data"	TEXT NOT NULL,
                PRIMARY KEY("id" AUTOINCREMENT)
            )''')

        # Insert a row of data
        # c.execute("INSERT INTO chain(hash, prev_hash, height, timestamp, data) VALUES (?, ?, 0, CURRENT_TIMESTAMP, '{}')", (uuid.uuid4().hex, uuid.uuid4().hex))

        # Save (commit) the changes
        # conn.commit()

        # We can also close the connection if we are done with it.
        # Just be sure any changes have been committed or they will be lost.
        # conn.close()

    else:
        conn = sqlite3.connect('%s.db' % current_name)
    return conn


conn2 = None
def get_conn2(current_name = None):
    global conn2
    if not conn2:
        conn2 = sqlite3.connect('%s.db' % current_name)
    return conn2

# connection = torndb.Connection("127.0.0.1", "nodes", user="root", password="root")
# connection_thread = torndb.Connection("127.0.0.1", "nodes", user="root", password="root")

# create_chain = """CREATE TABLE IF NOT EXISTS `chain%s` (
#     `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
#     `hash` varchar(64) NOT NULL DEFAULT '',
#     `prev_hash` varchar(64) NOT NULL DEFAULT '',
#     `height` int(11) unsigned NOT NULL,
#     `nonce` int(11) unsigned NOT NULL,
#     `difficulty` smallint(5) unsigned NOT NULL,
#     `identity` varchar(128) NOT NULL DEFAULT '',
#     `timestamp` int(11) unsigned NOT NULL,
#     `data` mediumtext NOT NULL,
#     PRIMARY KEY (`id`),
#     KEY `height` (`height`),
#     KEY `identity` (`identity`),
#     UNIQUE KEY `hash` (`hash`),
#     KEY `prev_hash` (`prev_hash`)
# ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
# """

# create_graph = """CREATE TABLE IF NOT EXISTS `graph%s` (
#     `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
#     `msgid` varchar(128) NOT NULL,
#     `timestamp` int(11) unsigned DEFAULT NULL,
#     `hash` varchar(128) NOT NULL DEFAULT '',
#     `from_block` varchar(128) NOT NULL DEFAULT '',
#     `to_block` varchar(128) NOT NULL DEFAULT '',
#     `nonce` int(10) unsigned NOT NULL,
#     `sender` varchar(128) NOT NULL,
#     `receiver` varchar(128) NOT NULL,
#     `data` text NOT NULL,
#     `insert_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
#     PRIMARY KEY (`id`),
#     UNIQUE KEY `hash` (`hash`),
#     UNIQUE KEY `msgid` (`msgid`),
#     KEY `from_block` (`from_block`,`sender`,`nonce`),
#     KEY `to_block` (`to_block`,`receiver`,`nonce`)
# ) ENGINE=InnoDB AUTO_INCREMENT=1000 DEFAULT CHARSET=utf8;
# """

# create_users = """CREATE TABLE `%susers` (
#     `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
#     `user_id` char(70) NOT NULL DEFAULT '',
#     `hash` char(32) NOT NULL DEFAULT '',
#     `node_id` varchar(100) NOT NULL DEFAULT '',
#     `object_size` int(10) unsigned NOT NULL,
#     `folder_size` int(10) unsigned NOT NULL,
#     `timestamp` int(10) unsigned NOT NULL,
#     `replication_id` tinyint(3) unsigned NOT NULL,
#     PRIMARY KEY (`id`),
#     KEY `user_id` (`user_id`)
# ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
# """

# create_roots = """CREATE TABLE `%sroots` (
#     `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
#     `hash` char(32) NOT NULL DEFAULT '',
#     `size` int(10) unsigned NOT NULL,
#     `timestamp` int(10) unsigned NOT NULL,
#     `tree` text NOT NULL,
#     PRIMARY KEY (`id`),
#     KEY `hash` (`hash`)
# ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
# """


def main():
    if not tree.current_name:
        return
    get_conn(tree.current_name)

    # if not connection.get("SELECT table_name FROM information_schema.tables WHERE table_schema = 'nodes' AND table_name = %s", tree.current_port+"chain"):
    # connection.execute("DROP TABLE IF EXISTS chain%s" % tree.current_port)
    # connection.execute(create_chain % tree.current_port)
    # connection.execute("TRUNCATE chain%s" % tree.current_port)

    # connection.execute("DROP TABLE IF EXISTS graph%s" % tree.current_port)
    # connection.execute(create_graph % tree.current_port)
    # connection.execute("TRUNCATE graph%s" % tree.current_port)

    # connection.execute("DROP TABLE IF EXISTS %susers" % tree.current_port)
    # connection.execute(create_users % tree.current_port)

    # connection.execute("DROP TABLE IF EXISTS %sroots" % tree.current_port)
    # connection.execute(create_roots % tree.current_port)
