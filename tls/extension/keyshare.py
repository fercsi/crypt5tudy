#!/usr/bin/python3
# RFC8446

from typing import NamedTuple
from tls.util import *
from .extension import Extension
from .supportedgroups import GROUP_IDS

class KeyShareEntry(NamedTuple):
    group: int
    key_exchange: bytes|None

class KeyShare(Extension):
    def __init__(self, group: str|int|None = None, key_exchange: bytes|None = None):
        super().__init__()
        self.extension_type = 51
        self.shares = []
        if key_exchange is not None:
            if group is None:
                raise TypeError('No group to key exchange given')
            self.add(group, key_exchange)

    def add(self, group: int, key_exchange: bytes | None = None) -> None:
        """Add group/key_exhange pair to KeyShare

        Note, that key_exchange might be missing in case of a `HelloRetryRequest`
        handshake records.
        """
        if isinstance(group, str):
            group = GROUP_IDS[group]
        self.shares.append(KeyShareEntry(group, key_exchange))

    def pack_extension_content(self):
        if self.handshake_type == 1:
            content = (pack_u16(n.group) + pack_bytes(bytes(n.key_exchange), 2) for n in self.shares)
            return pack_bytes_list(content, 2)
        elif self.handshake_type == 2:
            share = self.shares[0]
            if not self.hello_retry_request:
                key_exchange = bytes(share.key_exchange)
                return pack_u16(share.group) + pack_bytes(key_exchange, 2)
            else:
                return pack_u16(share.group)
        else:
            raise TypeError(f"Don't know, how to pack `KeyShare` for handshake type {self.handshake_type}")

    def unpack_extension_content(self, raw, *, record=None):
        if self.handshake_type == 1:
            key_share = unpack_bytes_list(raw, 0, 0, 2)
        elif self.handshake_type == 2:
            if record and record.hello_retry_request:
                group = unpack_u16(raw, 0)
                self.add(group)
                return
            key_share = [raw]
        else:
            raise TypeError(f"Don't know, how to unpack `SupportedVersion` for handshake type {self.handshake_type}")
        for key_share_entry in key_share:
            group = unpack_u16(key_share_entry, 0)
            key_exchange = unpack_bytes(key_share_entry, 2, 2)
            self.add(group, key_exchange)

    def represent(self, level: int = 0):
        text = super().represent(level);
        ind = '  '*level
        revlut = {}
        for k, v in GROUP_IDS.items():
            revlut[v] = k
        for v in self.shares:
            group = revlut.get(v.group) or f'unknown_{v.group:0>4x}';
            text += ind + f'  - group: {group}\n'
            text += ind + f'    key_exchange: {v.key_exchange.hex()}\n'
        return text
