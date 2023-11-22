#!/usr/bin/python3
# RFC8446

from enum import IntEnum
from util.serialize import *

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

class HandshakeType(TLSEnum8):
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    message_hash = 254
