
import os

import rocksdb
import mpt


conn = None
def get_conn(current_name = None):
    global conn
    if conn:
        return conn

    if not os.path.exists('miners'):
        os.makedirs('miners')
    conn = rocksdb.DB('miners/%s.db' % current_name, rocksdb.Options(create_if_missing=True))
    return conn


class DBWrap:
    def __init__(self, db) -> None:
        self.db = db

    def __setitem__(self, key, value):
        self.db.put(key, value)

    def __getitem__(self, key):
        return self.db.get(key)


def get_mpt(root=None):
    # storage = {}
    if not conn:
        raise

    storage = DBWrap(conn)
    m = mpt.MerklePatriciaTrie(storage, root=root)
    return m


def main():
    import tree
    if not tree.current_name:
        return
    get_conn(tree.current_name)
