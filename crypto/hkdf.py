#!/usr/bin/env python3
# RFC5869

from .hash import hmac
import struct
from typing import Callable

class HKDF:
    hash_function: Callable
    hash_size: int

    def __init__(self, hash_function: Callable|str):
        self.hash_function = hash_function
        self.hash_size = self.hash_function().digest_size

    def hmac_hash(self, key: bytes, data: bytes) -> bytes:
        return hmac(data, key=key, hash_function=self.hash_function).digest()

    def extract(self, salt: bytes|None, ikm: bytes) -> bytes:
        if salt is None:
            salt = b'\0' * self.hash_size
        if ikm is None:
            ikm = b'\0' * self.hash_size
        return self.hmac_hash(salt, ikm)

    def expand(self, prk: bytes, info: bytes, l: int) -> bytes:
        n = (l - 1) // self.hash_size + 1 # ceil(L/HashLen)
        t = b''
        ti = b''
        for i in range(1,n+1):
            ti = self.hmac_hash(prk, ti + info + bytes([i]))
            t += ti # T = T(1) | T(2) | T(3) | ... | T(N)
        return t[:l] # first L octets of T

    def expand_label(self, secret: bytes, label: str, context: bytes, length: int) -> bytes:
        # RFC8446 7.1
        hkdf_label = struct.pack('>H', length) \
            + bytes([6 + len(label)]) + ('tls13 ' + label).encode() \
            + bytes([len(context)]) + context
        return self.expand(secret, hkdf_label, length)

    def derive_secret(self, secret: bytes, label: str, messages: list[bytes]) -> bytes:
        # RFC8446 7.1
        transcript_hash = self.hash_function(b''.join(messages)).digest()
        return self.expand_label(secret, label, transcript_hash, self.hash_size)
