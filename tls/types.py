#!/usr/bin/python3
# RFC8446

from enum import IntEnum
from .util import *

class TLSEnum8(IntEnum):
    def to_bytes(self):
        return pack_u8(self.value)

class TLSEnum16(IntEnum):
    def to_bytes(self):
        return pack_u16(self.value)

class ContentType(TLSEnum8):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
