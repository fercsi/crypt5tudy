#!/usr/bin/python3

import math
import secrets
from crypto.modular import Modular
from util.serialize import *
from .groupinfo import FFDHGroup

class FFDH:
    def __init__(self, group: FFDHGroup):
        self.group = group
        self.M = Modular(group.p)

    def generate_key_pair(self, priv: bytes|int|None = None) -> (bytes, bytes):
        bits = self.group.bits
        size = bits + 7 >> 3

        g = self.M(self.group.g)
        p = self.group.p
        q = p >> 1
        if priv is None:
            priv = secrets.randbelow(q - 1) + 1
        if isinstance(priv, bytes):
            priv = int.from_bytes(priv, size)
        pub_m = g ** priv
        pub = pack_uint(int(pub_m), size)
        return priv, pub

    def create_secret(self, my_priv: bytes|int, peer_pub) -> bytes:
        bits = self.group.bits
        size = bits + 7 >> 3
        pub_m = self.M(unpack_uint(peer_pub, 0, size))
        if isinstance(my_priv, bytes):
            my_priv = unpack_uint(my_priv, 0, size)
        secret = pub_m ** my_priv
        return pack_uint(secret.value, size)
