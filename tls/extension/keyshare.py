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
        if self.handshakeType == 1:
            content = (packU16(n.method) + packBytes(n.key, 2) for n in self.keys)
            return packBytesList(content, 2)
        elif self.handshakeType == 2:
            key = self.keys[0]
            return packU16(key.method) + packBytes(key.key, 2)
        else:
            raise TypeError(f"Don't know, how to pack `KeyShare` for handshake type {self.handshakeType}")

    def unpackExtensionContent(self, raw):
        if self.handshakeType == 1:
            keyRawList = unpackBytesList(raw, 0, 0, 2)
        elif self.handshakeType == 2:
            keyRawList = [raw]
        else:
            raise TypeError(f"Don't know, how to unpack `SupportedVersion` for handshake type {self.handshakeType}")
        for keyRaw in keyRawList:
            keymethod = unpackU16(keyRaw, 0)
            keyData = unpackBytes(keyRaw, 2, 2)
            self.add(keyData, keymethod)

    def represent(self, level: int = 0):
        text = super().represent(level);
        ind = '  '*level
        revlut = {}
        for k, v in GROUP_IDS.items():
            revlut[v] = k
        for v in self.keys:
            method = revlut.get(v.method) or f'unknown_{v.method:0>4x}';
            text += ind + f'  - method: {method}\n'
            text += ind + f'    key: {v.key.hex()}\n'
        return text
