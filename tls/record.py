#!/usr/bin/python3
# RFC8446

import struct
from .util import *

class Record:
    def __init__(self, *, debug_level:int = 0):
        self.record_type = 0
        self.record_tlsversion = 0x0303
        self.debug_level = debug_level

    def pack(self) -> bytes:
        type = bytes([self.record_type])
        tlsver = self.record_tlsversion.to_bytes(2, 'big')
        content = self.pack_record_content()
        length = len(content).to_bytes(2, 'big')
        packed = type + tlsver + length + content
        return packed

    def pack_record_content(self) -> bytes:
        return b''

    def unpack(self, raw: bytes) -> None:
        self.raw_content = raw
        self.record_type = unpack_u8(raw, 0)
        self.record_tlsversion = unpack_u16(raw, 1)
        raw_content = unpack_bytes(raw, 3, 2)
        self.unpack_record_content(raw_content)

    def unpack_record_content(self, raw: bytes) -> None:
        pass

    def __str__(self) -> str:
        return self.represent()


class UnknownRecord(Record):
    def __init__(self, record_type: int, content: bytes = b''):
        super().__init__()
        self.record_type = record_type
        self.content = content

    def pack_record_content(self) -> bytes:
        return self.content

    def unpack_record_content(self, raw: bytes) -> None:
        self.content = raw

    def represent(self) -> str:
        return f'UnknownRecord_{self.record_type}:\n' \
            + f'  Content: {self.content.hex()}\n'
