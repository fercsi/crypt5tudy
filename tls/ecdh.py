#!/usr/bin/python3

import secrets
from crypto import ec
from util.serialize import *
from .groupinfo import WeierstrassGroup, MontgomeryGroup

def ECDH(group: WeierstrassGroup|MontgomeryGroup):
    if isinstance(group, WeierstrassGroup):
        return ECDHWeierstrass(group)
    elif isinstance(group, MontgomeryGroup):
        return ECDHMontgomery(group)
    else:
        raise TypeError('Invalid EC group')

class ECDHWeierstrass:
    class PublicKey:
        size: int
        x: int
        y: int
        def __init__(self, size:int, x:int, y:int):
            self.size = size
            self.x = x
            self.y = y
        def __bytes__(self) -> bytes:
            return b'\x04' + pack_int(self.x, self.size) + pack_int(self.y, self.size)

    def __init__(self, group: WeierstrassGroup):
        self.group = group
        self.ec = ec.Weierstrass(a=group.a, b=group.b, p=group.p)

    def generate_key_pair(self, priv: bytes|int|None = None) -> (bytes, bytes):
        bits = self.group.bits
        size = bits + 7 >> 3
        G = self.ec(self.group.Gx, self.group.Gy)
        if priv is None:
            priv = secrets.randbelow(self.group.p)
        if isinstance(priv, bytes):
            priv = int.from_bytes(priv, size)
        pub_ec = priv * G
#>        pub = ECDHWeierstrass.PublicKey(size, pub_ec.x, pub_ec.y)
        pub = b'\x04' + pack_int(pub_ec.x, size) + pack_int(pub_ec.y, size)
        return priv, pub

    def create_secret(self, my_priv: bytes|int, peer_pub) -> bytes:
        bits = self.group.bits
        size = bits + 7 >> 3
#>        pub_ec = self.ec(peer_pub.x, peer_pub.y)
        pub_ec = self.ec(
            unpack_int(peer_pub, 1, size),
            unpack_int(peer_pub, size+1, size)
        )
        if isinstance(my_priv, bytes):
            my_priv = int.from_bytes(my_priv, size)
        secret = my_priv * pub_ec
        return pack_int(secret.x, size)


class ECDHMontgomery:
#>    # NOTE: ECDH packing is little endian!
#>    def __init__(self, group: WeierstrassGroup|MontgomeryGroup):
#>        self.group = group
#>        if isinstance(group, WeierstrassGroup):
#>            self.ec = ec.Weierstrass(a=group.a, b=group.b)
#>        elif isinstance(group, MontgomeryGroup):
#>            self.ec = ec.Montgomery(A=group.A, p=group.p, bits=group.bits)
#>        else:
#>            raise TypeError('Invalid EC group')

    def __init__(self, group: MontgomeryGroup):
        self.group = group
        self.ec = ec.Montgomery(A=group.A, p=group.p, bits=group.bits)

    def decode_ucoordinate(self, u: bytes) -> int:
        bits = self.group.bits
        u_i = int.from_bytes(u, 'little')
        return u_i & ((1 << bits) - 1)

    def encode_ucoordinate(self, u: int, p: int) -> bytes:
        bits = self.group.bits
        u = u % p
        return u.to_bytes((bits + 7 >> 3), 'little')

    def decode_scalar(self, k: bytes) -> int:
        bits = self.group.bits
        cofactor = self.group.cofactor
        k_i = int.from_bytes(k, 'little')
        return k_i & ~(cofactor - 1) | (1 << bits - 1)

    def apply(self, k: bytes, u: bytes) -> bytes:
        bits = self.group.bits
        p = self.group.p
        k_i = self.decode_scalar(k)
        u_ec = self.ec(self.decode_ucoordinate(u))
        r_ec = k_i * u_ec
        return self.encode_ucoordinate(int(r_ec), p)

    def generate_key_pair(self, priv: bytes|int|None = None) -> (bytes, bytes):
        bits = self.group.bits
        size = bits + 7 >> 3
        cofactor = self.group.cofactor
        U_P = self.group.U_P
        g = U_P.to_bytes(size, 'little')
        if priv is None:
            priv_n = secrets.randbits(bits - 1) \
                                        & ~(cofactor - 1) | (1 << bits - 1)
            priv = priv_n.to_bytes(size, 'little')
        if isinstance(priv, int):
            priv = priv.to_bytes(size, 'big')
        pub = self.apply(priv, g)
        return priv, pub

    def create_secret(self, my_priv: bytes, peer_pub: bytes) -> bytes:
        return self.apply(my_priv, peer_pub)
