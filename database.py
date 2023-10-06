
import os
import tempfile

import rocksdb


conn = None
def get_conn(current_name = None):
    global conn
    if conn:
        return conn

    if not os.path.exists('users'):
        os.makedirs('users')
    conn = rocksdb.DB('users/%s.db' % current_name, rocksdb.Options(create_if_missing=True))
    return conn


temp_conn = None
def get_temp_conn():
    global temp_conn

    tempdir = tempfile.mkdtemp()
    temp_conn = rocksdb.DB('%s/temp.db' % tempdir, rocksdb.Options(create_if_missing=True))
    return temp_conn


