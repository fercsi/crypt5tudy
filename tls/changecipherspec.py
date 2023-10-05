#!/usr/bin/python3
# RFC8446 (RFC5246) No affect in TLS1.3

from tls.util import *
from tls.record import Record

class ChangeCipherSpec(Record):
    def __init__(self):
        super().__init__()
        self.recordType = 20
        self.type = 1

    def packRecordContent(self) -> bytes:
        return packU8(self.type)

    def unpackRecordContent(self, raw: bytes) -> None:
        self.type = unpackU8(raw, 0)

    def represent(self) -> str:
        t = 'change_cipher_spec' if self.type==1 else f'unknown_{self.type:0>2x}'
        return f'ChangeCipherSpec: {t}\n'
