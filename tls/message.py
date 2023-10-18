#!/usr/bin/python3
# RFC8446

import struct
#>from enum import IntEnum

from .util import *

#>class ContentType(IntEnum):
#>    invalid = 0
#>    change_cipher_spec = 20
#>    alert = 21
#>    handshake = 22
#>    application_data = 23
#>    _MAX = 255
#>
class Message:
    def __init__(self, *, debug_level:int = 0):
        self.message_type = 0
        self.message_tlsversion = 0x0303
        self.debug_level = debug_level

    def pack(self) -> bytes:
        type = bytes([self.message_type])
        tlsver = self.message_tlsversion.to_bytes(2, 'big')
        content = self.pack_message_content()
        length = len(content).to_bytes(2, 'big')
        packed = type + tlsver + length + content
        return packed

    def pack_message_content(self) -> bytes:
        return b''

    def unpack(self, raw: bytes) -> None:
        self.raw_content = raw
        self.unpack_message_content(self.raw_content)

    def unpack_message_content(self, raw: bytes) -> None:
        pass

    def __str__(self) -> str:
        return self.represent()


class UnknownMessage(Message):
    def __init__(self, message_type: int, content: bytes = b''):
        super().__init__()
        self.message_type = message_type
        self.content = content

    def pack_message_content(self) -> bytes:
        return self.content

    def unpack_message_content(self, raw: bytes) -> None:
        self.content = raw

    def represent(self) -> str:
        return f'UnknownMessage_{self.message_type}:\n' \
            + f'  Content: {self.content.hex()}\n'
