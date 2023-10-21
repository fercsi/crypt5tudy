#!/usr/bin/python3
# RFC2104

import struct
from typing import Callable
from .hashfunction import HashFunction
from .registry import Registry

class hmac(HashFunction):
    digest_size = None
    block_size = None

    _hash_function: Callable

    def init(self, *, key: bytes, hash_function: Callable|str) -> None:
        if isinstance(hash_function, str):
            hash_function = Registry.get(hash_function)
        if not callable(hash_function):
            raise TypeError('Invalid hash function')
        self._inner_hash_function = hash_function()
        self._outer_hash_function = hash_function()
        self._digest_size = self._inner_hash_function.digest_size
        self._block_size = self._inner_hash_function.block_size

        if len(key) > self._block_size:
            raise ValueError('Invalid key size')
        key = key + b'\0' * (self._block_size - len(key))

        ipad = b'\x36' * self._block_size
        self._inner_hash_function.update(_xor(ipad, key))
        opad = b'\x5c' * self._block_size
        self._outer_hash_function.update(_xor(opad, key))

    def update(self, message: bytes) -> None:
        self._inner_hash_function.update(message)

    def digest(self) -> bytes:
        inner_hash = self._inner_hash_function.digest()
        outer_hash_function = self._outer_hash_function.copy()
        outer_hash_function.update(inner_hash)
        return outer_hash_function.digest()


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes((x ^ y for x, y in zip(a, b)))


Registry.add(hmac, 'hmac')
