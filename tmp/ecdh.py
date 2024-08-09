#!/usr/bin/python3

import random
from crypto import ec

def decode_little_endian(b):
    return int.from_bytes(b, 'little')

def decode_ucoordinate(u, bits=255):
    u = decode_little_endian(u)
    return u & ((1 << bits) - 1)

def encode_ucoordinate(u, p, bits=255):
    u = u % p
    return u.to_bytes((bits+7>>3), 'little')

def decode_scalar25519(k):
    k = decode_little_endian(k)
    return k & ((1<<255) - 8) | (1<<254)

def decode_scalar448(k):
    k = decode_little_endian(k)
    return k & ((1<<448) - 4) | (1<<447)

def x25519(k, u):
    k = decode_scalar25519(k)
    bits = ec.EC25519.bits
    u = ec.EC25519(decode_ucoordinate(u, bits))
    u2 = k * u
    return encode_ucoordinate(int(u2), u2.p, bits)

def generate_key_pairX25519():
    g = (9).to_bytes(32, 'little')
    privN = random.randint(2**251, 2**252-1) << 3
    priv = privN.to_bytes(32, 'little')
    pub = x25519(priv, g)
    return priv, pub

def create_secret(my_priv, their_pub):
    return x25519(my_priv, their_pub)
