#!/usr/bin/env python3
# RFC5869

import hashlib
import hmac
import struct
from typing import Callable

class HKDF:
    hashFunction: Callable
    hashSize: int

    def __init__(self, hashFunction: Callable|str):
        if isinstance(hashFunction, str):
            self.hashFunction = getattr(hashlib, hashFunction.lower(), None)
            if self.hashFunction is None:
                raise TypeError(f'Hash type "{hashFunction}" is not supported')
        else:
            self.hashFunction = hashFunction
        self.hashSize = self.hashFunction().digest_size

    def hmacHash(self, key: bytes, data: bytes) -> bytes:
        # RFC2104
        return hmac.new(key, data, self.hashFunction).digest()

    def extract(self, salt: bytes|None, ikm: bytes) -> bytes:
        if salt is None:
            salt = b'\0' * self.hashSize
        if ikm is None:
            ikm = b'\0' * self.hashSize
        return self.hmacHash(salt, ikm)

    def expand(self, prk: bytes, info: bytes, l: int) -> bytes:
        n = (l - 1) // self.hashSize + 1 # ceil(L/HashLen)
        t = b''
        ti = b''
        for i in range(1,n+1):
            ti = self.hmacHash(prk, ti + info + bytes([i]))
            t += ti # T = T(1) | T(2) | T(3) | ... | T(N)
        return t[:l] # first L octets of T

    def expandLabel(self, secret: bytes, label: str, context: bytes, length: int) -> bytes:
        # RFC8446 7.1
        hkdfLabel = struct.pack('>H', length) \
            + bytes([6 + len(label)]) + ('tls13 ' + label).encode() \
            + bytes([len(context)]) + context
        return self.expand(secret, hkdfLabel, length)

    def deriveSecret(self, secret: bytes, label: str, messages: list[bytes]) -> bytes:
        # RFC8446 7.1
        transcriptHash = self.hashFunction(b''.join(messages)).digest()
        return self.expandLabel(secret, label, transcriptHash, self.hashSize)
