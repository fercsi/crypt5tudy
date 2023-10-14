#!/usr/bin/python3

import secrets
from crypto import ec
from .util import unpack_int_le
from .groupinfo import WeierstrassGroup, MontgomeryGroup

class ECDH:
    # NOTE: ECDH packing is little endian!
    def __init__(self, group: WeierstrassGroup|MontgomeryGroup):
        self.group = group
        if isinstance(group, WeierstrassGroup):
            self.ec = ec.Weierstrass(a=group.a, b=group.b)
        elif isinstance(group, MontgomeryGroup):
            self.ec = ec.Montgomery(A=group.A, p=group.p, bits=group.bits)
        else:
            raise TypeError('Invalid EC group')

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

    def generate_key_pair(self, priv: bytes|None = None) -> (bytes, bytes):
        bits = self.group.bits
        size = bits + 7 >> 3
        cofactor = self.group.cofactor
        U_P = self.group.U_P
        g = U_P.to_bytes(size, 'little')
        if priv is None:
            priv_n = secrets.randbits(bits - 1) \
                                        & ~(cofactor - 1) | (1 << bits - 1)
            priv = priv_n.to_bytes(size, 'little')
        pub = self.apply(priv, g)
        return priv, pub

    def create_secret(self, my_priv: bytes, peer_pub: bytes) -> bytes:
        return self.apply(my_priv, peer_pub)
