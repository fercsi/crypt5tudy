#!/usr/bin/python3
# RFC8446

from tls.util import *
from .handshake import Handshake

class Finished(Handshake):
    def __init__(self, verify_data: bytes = b''):
        super().__init__()
        self.handshake_type = 20
        self.verify_data = verify_data

    def pack_handshake_content(self):
        return self.verify_data

    def unpack_handshake_content(self, raw):
        self.verify_data = raw

    def represent(self):
        verify_data = self.verify_data.hex()
        return "Handshake-finished:\n"       \
             + f"  VerifyData: {verify_data}\n"
