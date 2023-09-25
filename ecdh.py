#!/usr/bin/python3

import random
import ec

def decodeLittleEndian(b):
    return int.from_bytes(b, 'little')

def decodeUCoordinate(u, bits=255):
    u = decodeLittleEndian(u)
    return u & ((1 << bits) - 1)

def encodeUCoordinate(u, p, bits=255):
    u = u % p
    return u.to_bytes((bits+7>>3), 'little')

def decodeScalar25519(k):
    k = decodeLittleEndian(k)
    return k & ((1<<255) - 8) | (1<<254)

def decodeScalar448(k):
    k = decodeLittleEndian(k)
    return k & ((1<<448) - 4) | (1<<447)

def x25519(k, u):
    k = decodeScalar25519(k)
    bits = ec.EC25519.bits
    u = ec.EC25519(decodeUCoordinate(u, bits))
    u2 = k * u
    return encodeUCoordinate(int(u2), u2.p, bits)

def generateKeyPairX25519():
    g = (9).to_bytes(32, 'little')
    privN = random.randint(2**251, 2**252-1) << 3
    priv = privN.to_bytes(32, 'little')
    pub = x25519(priv, g)
    return priv, pub

def createSecret(myPriv, theirPub):
    return x25519(myPriv, theirPub)
