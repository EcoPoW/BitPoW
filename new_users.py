
import os
import secrets
import eth_keys

if not os.path.exists('users'):
    os.makedirs('users')

f = open("users/sk.keys", "wb")
for i in range(100000):
    raw_key = secrets.token_bytes(32)
    f.write(raw_key)

    sk = eth_keys.keys.PrivateKey(raw_key)
    print(sk.public_key.to_checksum_address())

    # f2 = open("users/sk%s.key" % i, "rb")
    # sk2 = eth_keys.keys.PrivateKey(f2.read())
    # print(sk2.public_key.to_canonical_address())
    # f2.close()
f.close()
