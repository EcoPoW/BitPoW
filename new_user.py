import os
import secrets
import eth_keys

if not os.path.exists('users'):
    os.makedirs('users')

f = open("users/user2.key", "wb")
raw_key = secrets.token_bytes(32)
f.write(raw_key)
f.close()
