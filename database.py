
import os

import tree
import rocksdb

conn = None
def get_conn(current_name = None):
    global conn
    if conn:
        return conn

    if not os.path.exists('miners'):
        os.makedirs('miners')
    conn = rocksdb.DB('miners/%s.db' % current_name, rocksdb.Options(create_if_missing=True))
    return conn


def main():
    if not tree.current_name:
        return
    get_conn(tree.current_name)
