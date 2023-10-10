#!/usr/bin/python3
# RFC8446 (RFC5246) No affect in TLS1.3

from tls.util import *
from tls.record import Record

class ApplicationData(Record):
    def __init__(self, cipher_text: bytes = b''):
        super().__init__()
        self.record_type = 23
        self.cipher_text = cipher_text

    def pack_record_content(self) -> bytes:
        return self.cipher_text

    def unpack_record_content(self, raw: bytes) -> None:
#>        self.cipher_text = raw
        self.auth_data = self.raw_content[:5]
        self.auth_tag = raw[-16:]
        self.cipher_text = raw[:-16]

    def represent(self) -> str:
        return f'ApplicationData:\n  CipherText: {self.cipher_text.hex()}\n'
