from __future__ import print_function

import hashlib
import secrets

import ecdsa


def byte_xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])


# def new_key():
#     secexp = ecdsa.util.randrange(ecdsa.SECP256k1.order)
#     return ecdsa.util.number_to_string(secexp, ecdsa.SECP256k1.order)


def load_sk(sk_bytes: bytes):
    # secexp = ecdsa.util.randrange(ecdsa.SECP256k1.order)
    assert len(sk_bytes) == 32
    secexp = ecdsa.util.string_to_number(sk_bytes)
    pubkey_point = ecdsa.SECP256k1.generator * secexp
    pubkey = ecdsa.ecdsa.Public_key(ecdsa.SECP256k1.generator, pubkey_point)
    pubkey.order = ecdsa.SECP256k1.order
    return ecdsa.ecdsa.Private_key(pubkey, secexp)


def load_pk(pk_bytes: bytes):
    pubkey_point = ecdsa.ellipticcurve.PointJacobi.from_bytes(ecdsa.ecdsa.curve_secp256k1, pk_bytes)
    pubkey = ecdsa.ecdsa.Public_key(ecdsa.SECP256k1.generator, pubkey_point)
    return pubkey


# D = (gECC^skA)^d, d = H(skA, r)
# r
# E = H(m, w)
# F = H(gECC^d, E) xor (m||w)
def encrypt(sk, cleartext: bytes, r = None):
    if not r:
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
        # print('m||w', mw)
        cleartext += mw[:-16]

    return cleartext


# D_B = (gECC^skB)^d, d = H(skA, r)
def rekey(sk, r, pk):
    h = hashlib.blake2b()
    h.update(ecdsa.util.number_to_string(sk.secret_multiplier, ecdsa.SECP256k1.order))
    h.update(ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order))
    d = ecdsa.util.string_to_number(h.digest())
    # print('d = H(a, r)', d, sk.secret_multiplier, r)

    D = pk.point * d
    # print('D', D)
    return D.to_bytes()


if __name__ == '__main__':
    key_a = secrets.token_bytes(32)
    sk_a = load_sk(key_a)
    rk_a, r, encrypted = encrypt(sk_a, b'123'*50)
    print(r)

    decrypted = decrypt(sk_a, rk_a, encrypted)
    print(decrypted)

    key_b = secrets.token_bytes(32)
    sk_b = load_sk(key_b)
    rk_b = rekey(sk_a, r, sk_b.public_key)
    decrypted = decrypt(sk_b, rk_b, encrypted)
    print(decrypted)

    # in this case, we did not change r
    rk_a, r, encrypted = encrypt(sk_a, b'456'*5, r)
    print(r)

    # B can still decrypt with previous generated rk_b
    decrypted = decrypt(sk_b, rk_b, encrypted)
    print(decrypted)
