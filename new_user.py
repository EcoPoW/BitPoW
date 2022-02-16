
import os
import secrets
import eth_keys

if not os.path.exists('users'):
    os.makedirs('users')

for i in range(10):
    raw_key = secrets.token_bytes(32)
    f = open("users/sk%s.key" % i, "wb")
    f.write(raw_key)
    f.close()

    sk = eth_keys.keys.PrivateKey(raw_key)
    print(sk.public_key.to_checksum_address())

    f2 = open("users/sk%s.key" % i, "rb")
    sk2 = eth_keys.keys.PrivateKey(f2.read())
    print(sk2.public_key.to_canonical_address())
    f.close()
