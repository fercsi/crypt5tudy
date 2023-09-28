#!/usr/bin/python3
# RFC8446

from typing import NamedTuple
from tls.util import *
from .extension import Extension
from .supportedgroups import GROUP_IDS

class KeyInfo(NamedTuple):
    key: bytes
    method: int

class KeyShare(Extension):
    def __init__(self, key: bytes|None = None, method: str|int|None = None):
        super().__init__()
        self.extensionType = 51
        self.keys = []
        if key is not None:
            if method is None:
                raise TypeError('Kex method is not given')
            self.add(key, method)

    def add(self, key: bytes, method: int) -> None:
        if isinstance(method, str):
            method = GROUP_IDS[method]
        self.keys.append(KeyInfo(key, method))

    def packExtensionContent(self):
        content = (packU16(n.method) + packBytes(n.key, 2) for n in self.keys)
        return packBytesList(content, 2)
