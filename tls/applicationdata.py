#!/usr/bin/python3
# RFC8446 (RFC5246) No affect in TLS1.3

from tls.util import *
from tls.record import Record

class ApplicationData(Record):
    def __init__(self, content: bytes = b''):
        super().__init__()
        self.record_type = 23
        self.content = content

    def pack_record_content(self) -> bytes:
        return self.content

    def unpack_record_content(self, raw: bytes) -> None:
#>        self.cipher_text = raw
#>        self.auth_data = self.raw_content[:5]
        self.content = raw
        # TODO: remove
#>        self.auth_tag = raw[-16:] # Note, that this is true only in major cases!
#>        self.cipher_text = raw[:-16]

    def represent(self) -> str:
        return f'ApplicationData:\n  Content: {self.content.hex()}\n'
