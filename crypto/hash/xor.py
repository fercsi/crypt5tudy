#!/usr/bin/python3

from functools import reduce
from .hashfunction import HashFunction

class xor8(HashFunction):
    digest_size: int = 8
    block_size: int = 8
    _xor: int

    def init(self) -> None:
        self._xor = 0

    def update(self, data: bytes) -> None:
        self._xor = self._xor ^ reduce(lambda a,b: a^b, data)

    def final(self) -> bytes:
        return bytes([self._xor])
