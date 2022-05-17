from __future__ import print_function

import time
import hashlib

import ecdsa

l512 = 2**512-1


def byte_xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])


secexp = ecdsa.util.randrange(ecdsa.SECP256k1.order)
assert 1 <= secexp < ecdsa.SECP256k1.order
pubkey_point = ecdsa.SECP256k1.generator*secexp
pubkey = ecdsa.ecdsa.Public_key(ecdsa.SECP256k1.generator, pubkey_point)
pubkey.order = ecdsa.SECP256k1.order

skA = ecdsa.ecdsa.Private_key(pubkey, secexp)
# print(skA)

secexp = ecdsa.util.randrange(ecdsa.SECP256k1.order)
assert 1 <= secexp < ecdsa.SECP256k1.order
pubkey_point = ecdsa.SECP256k1.generator*secexp
pubkey = ecdsa.ecdsa.Public_key(ecdsa.SECP256k1.generator, pubkey_point)
pubkey.order = ecdsa.SECP256k1.order

skB = ecdsa.ecdsa.Private_key(pubkey, secexp)
# print(skB)

# D = (gECC^skA)^d, d = H(skA, r)
# E = g^e, e = H(m, w)       ->  E = H(m, w)
# F = H(g^d, E)) xor (m||w)  ->  F = H(gECC^d, E)) xor (m||w)
# V = gECC^v, v <- Zp
# S = gECC^s, s = v + skA * r

t0 = time.time()

gECC = ecdsa.SECP256k1.generator
print('gECC', gECC)

# p = numbertheory.next_prime(2**191)
# print('p', p)

# g = ecdsa.util.randrange(ecdsa.SECP256k1.order)
# print('g', g)

a = skA.secret_multiplier
print('skA', a)
print('pkA', skA.public_key.point)

r = ecdsa.util.randrange(ecdsa.SECP256k1.order)
print('r', r)

h = hashlib.blake2b()
h.update(ecdsa.util.number_to_string(a, ecdsa.SECP256k1.order))
h.update(ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order))
d = ecdsa.util.string_to_number(h.digest())
print('d = H(a, r)', d)

# D = (gECC^skA)^d, d = H(skA, r)
D = skA.public_key.point * d
print('D', D)
# print('D', gECC*d*a)

gECC_d = D*ecdsa.numbertheory.inverse_mod(a, ecdsa.SECP256k1.order)
print('gECC^d', gECC_d)
# print('gECC^d', gECC*d)

m = b'This is the PRE!This is the PRE!This is the PRE!' #64-16 bytes
w = b'1234567890abcdef'

# V = g^v
v = ecdsa.util.randrange(ecdsa.SECP256k1.order)
V = skA.public_key.generator * v
# V = numbertheory.modular_exp(g, v, l192)
# print('V', V)

# t1 = time.time()
# print('Setup TIME >>>>>>>>>', t1 - t0)
# for x in range(10):
#     for y in range(10):

# E = g^e, e = H(m, w)
h = hashlib.blake2b()
h.update(m)
h.update(w)
# e = ecdsa.util.string_to_number(h.digest())
E = h.digest()
# print('e = H(m, w)', e)

# E = ecdsa.numbertheory.modular_exp(g, e, ecdsa.SECP256k1.order)
# E = skA.public_key.generator * r
# print('E = g^e', E)

# F = H(g^d, E)) xor (m||w)
h = hashlib.blake2b()
h.update(ecdsa.util.number_to_string(gECC_d.x(), ecdsa.SECP256k1.order))
# h.update(ecdsa.util.number_to_string(E, ecdsa.SECP256k1.order))
h.update(E)
k = ecdsa.util.string_to_number(h.digest())
j = ecdsa.util.string_to_number(m+w)
c = k^j
# print('k', k)
print('c', c)
# F = util.number_to_string(c, l512)
F = byte_xor(h.digest(), m+w)
# print('F = H(gECC^d, E)) xor (m||w)', F)

    # t2 = time.time()
    # print('TIME >>>>>>>>>', t2 - t0)

print('m||w', ecdsa.util.number_to_string(c^k, l512))

# s = v + a * r
s = v + a * r
print('s = v + a * r', s)


S = skA.public_key.generator * s
print('S', S)
print('V*g^(skA*r)', V + skA.public_key.generator*(a*r))
print('g^s ?= V*pkA^r', S == V + skA.public_key.generator*(a*r))

#rk = (g^b/g^a)^d
b = skB.secret_multiplier
rk = gECC * ((b-a) * d)
print('rk', rk)

# A generates the key DB replacing D
DB = D + rk
print('DB', DB)
# DB = skB.privkey.public_key.point * d
# print('DB', DB)

# B using the skB and DB to get g^d
# g^d = DB^(1/b)
gECC_d2 = DB * ecdsa.numbertheory.inverse_mod(b, ecdsa.SECP256k1.order)
print('gECC^d2', gECC_d2.x())
# print('gECC^d', gECC_d)

gECC_d3 = D * ecdsa.numbertheory.inverse_mod(a, ecdsa.SECP256k1.order)
print('gECC^d3', gECC_d3.x())


# B decode
h = hashlib.blake2b()
h.update(ecdsa.util.number_to_string(gECC_d2.x(), ecdsa.SECP256k1.order))
# h.update(ecdsa.util.number_to_string(E, ecdsa.SECP256k1.order))
h.update(E)
k = ecdsa.util.string_to_number(h.digest())
print('k', k)
c = ecdsa.util.string_to_number(F)
print('F', F)
print('m||w', ecdsa.util.number_to_string(c^k, l512))


def new_key():
    secexp = ecdsa.util.randrange(ecdsa.SECP256k1.order)
    return ecdsa.util.number_to_string(secexp, ecdsa.SECP256k1.order)

def load_key(sk_bytes: bytes):
    # secexp = ecdsa.util.randrange(ecdsa.SECP256k1.order)
    assert len(sk_bytes) == 32
    secexp = ecdsa.util.string_to_number(sk_bytes)
    pubkey_point = ecdsa.SECP256k1.generator * secexp
    pubkey = ecdsa.ecdsa.Public_key(ecdsa.SECP256k1.generator, pubkey_point)
    pubkey.order = ecdsa.SECP256k1.order
    return ecdsa.ecdsa.Private_key(pubkey, secexp)

# D = (gECC^skA)^d, d = H(skA, r)
# r
# E = H(m, w)
# F = H(gECC^d, E)) xor (m||w)
def encrypt(sk, cleartext: bytes):
    r = ecdsa.util.randrange(ecdsa.SECP256k1.order)
    # print('r', r)

    h = hashlib.blake2b()
    h.update(ecdsa.util.number_to_string(sk.secret_multiplier, ecdsa.SECP256k1.order))
    h.update(ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order))
    d = ecdsa.util.string_to_number(h.digest())
    # print('d = H(a, r)', d, sk.secret_multiplier, r)

    D = sk.public_key.point * d
    # print('D', D.x())
    # print('D', gECC*d*a)
    gECC_d = ecdsa.SECP256k1.generator * d
    # print('gECC_d', gECC_d.x())

    ciphertext = b''
    for i in range(0, len(cleartext), 48):
        # print(i, data[i:i+48])
        m = cleartext[i:i+48]
        iv = ecdsa.util.randrange(2**128-1)
        w = ecdsa.util.number_to_string(iv, 2**128-1)
        # print(len(w), w)

        h = hashlib.blake2b()
        h.update(m)
        h.update(w)
        E = h.digest()

        h = hashlib.blake2b()
        h.update(ecdsa.util.number_to_string(gECC_d.x(), ecdsa.SECP256k1.order))
        h.update(E)
        F = byte_xor(h.digest(), m+w)
        # print(i, E, F)
        ciphertext += (E+F)

    # print(len(ciphertext))

    return D.to_bytes(), r, ciphertext


def decrypt(sk, rk, ciphertext):
    # D = ecdsa.ellipticcurve.PointJacobi(ecdsa.ecdsa.curve_secp256k1, rk[0], rk[1], 1, ecdsa.SECP256k1.order)
    D = ecdsa.ellipticcurve.PointJacobi.from_bytes(ecdsa.ecdsa.curve_secp256k1, rk)
    # print('D', D.x())
    gECC_d = D * ecdsa.numbertheory.inverse_mod(sk.secret_multiplier, ecdsa.SECP256k1.order)
    # print('gECC_d', gECC_d.x())

    cleartext = b''
    for i in range(0, len(ciphertext), 128):
        # print(i, ciphertext)
        # print(i, ciphertext[i: i+64], ciphertext[i+64: i+128])
        E = ciphertext[i: i+64]
        F = ciphertext[i+64: i+128]

        h = hashlib.blake2b()
        h.update(ecdsa.util.number_to_string(gECC_d.x(), ecdsa.SECP256k1.order))
        h.update(E)
        mw = byte_xor(F, h.digest())
        print('m||w', mw)
        cleartext += mw[:-16]

    return cleartext

def rekey(sk, r, pk):
    # print(rk, sk, pk)
    # r = rk[1]

    h = hashlib.blake2b()
    h.update(ecdsa.util.number_to_string(sk.secret_multiplier, ecdsa.SECP256k1.order))
    h.update(ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order))
    d = ecdsa.util.string_to_number(h.digest())
    # print('d = H(a, r)', d, sk.secret_multiplier, r)

    D = pk.point * d
    print('D', D)
    return D.to_bytes()


print('======')
key_a = new_key()
sk_a = load_key(key_a)
rk_a, r, encrypted = encrypt(sk_a, b'123'*50)
# print(encrypt(sk_a, b''))

decrypted = decrypt(sk_a, rk_a, encrypted)
print(decrypted)

key_b = new_key()
sk_b = load_key(key_b)
rk_b = rekey(sk_a, r, sk_b.public_key)
decrypted = decrypt(sk_b, rk_b, encrypted)
print(decrypted)

