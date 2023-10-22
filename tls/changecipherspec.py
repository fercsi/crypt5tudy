#!/usr/bin/python3
# RFC8446 (RFC5246) No affect in TLS1.3

from util.serialize import *
from tls.message import Message

class ChangeCipherSpec(Message):
    def __init__(self):
        super().__init__()
        self.message_type = 20
        self.type = 1

    def pack_message_content(self) -> bytes:
        return pack_u8(self.type)

    def unpack_message_content(self, raw: bytes) -> None:
        self.type = unpack_u8(raw, 0)

    def represent(self) -> str:
        t = 'change_cipher_spec' if self.type==1 else f'unknown_{self.type:0>2x}'
        return f'ChangeCipherSpec: {t}\n'
