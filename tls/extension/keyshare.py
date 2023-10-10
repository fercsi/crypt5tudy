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
        self.extension_type = 51
        self.keys = []
        if key is not None:
            if method is None:
                raise TypeError('Kex method is not given')
            self.add(key, method)

    def add(self, key: bytes, method: int) -> None:
        if isinstance(method, str):
            method = GROUP_IDS[method]
        self.keys.append(KeyInfo(key, method))

    def pack_extension_content(self):
        if self.handshake_type == 1:
            content = (pack_u16(n.method) + pack_bytes(n.key, 2) for n in self.keys)
            return pack_bytes_list(content, 2)
        elif self.handshake_type == 2:
            key = self.keys[0]
            return pack_u16(key.method) + pack_bytes(key.key, 2)
        else:
            raise TypeError(f"Don't know, how to pack `KeyShare` for handshake type {self.handshake_type}")

    def unpack_extension_content(self, raw):
        if self.handshake_type == 1:
            key_raw_list = unpack_bytes_list(raw, 0, 0, 2)
        elif self.handshake_type == 2:
            key_raw_list = [raw]
        else:
            raise TypeError(f"Don't know, how to unpack `SupportedVersion` for handshake type {self.handshake_type}")
        for key_raw in key_raw_list:
            keymethod = unpack_u16(key_raw, 0)
            key_data = unpack_bytes(key_raw, 2, 2)
            self.add(key_data, keymethod)

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
