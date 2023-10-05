#!/usr/bin/python3
# RFC8446 (RFC5246) No affect in TLS1.3

from tls.util import *
from tls.record import Record

class ApplicationData(Record):
    def __init__(self, cipherText: bytes = b''):
        super().__init__()
        self.recordType = 23
        self.cipherText = cipherText

    def packRecordContent(self) -> bytes:
        return self.cipherText

    def unpackRecordContent(self, raw: bytes) -> None:
        self.cipherText = raw

    def represent(self) -> str:
        return f'ApplicationData: {self.cipherText.hex()}\n'
