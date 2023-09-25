#!/usr/bin/python3
# RFC8446

import struct
from .util import *

class Record:
    def __init__(self):
        self.recordType = 0
        self.recordTLSVersion = 0x0301

    def pack(self) -> bytes:
        type = bytes([self.recordType])
        tlsver = self.recordTLSVersion.to_bytes(2, 'big')
        content = self.packRecordContent()
        length = len(content).to_bytes(2, 'big')
        packed = type + tlsver + length + content
        return packed

    def packRecordContent(self) -> bytes:
        return b''

    def unpack(self, raw: bytes) -> None:
        self.recordTLSVersion = unpackU16(raw, 1)
        rawContent = unpackBytes(raw, 3, 2)
        self.unpackRecordContent(rawContent)

    def packRecordContent(self, raw: bytes) -> None:
        pass


class UnknownRecord(Record):
    def __init__(self, recordType: int, content: bytes = b''):
        super().__init__()
        self.recordType = recordType
        self.content = content

    def packRecordContent(self) -> bytes:
        return self.content

    def packRecordContent(self, raw: bytes) -> None:
        self.content = raw
