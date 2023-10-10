#!/usr/bin/python3
# RFC8446

from tls.util import *
from .handshake import Handshake

class EncryptedExtensions(Handshake):
    def __init__(self, cipher_suite: list|None = None):
        super().__init__()
        self.handshake_type = 8
        self.encrypted_extensions_tlsversion = 0x0303

    def pack_handshake_content(self):
        exts = self.pack_extensions()
        return exts

    def unpack_handshake_content(self, raw):
        self.unpack_extensions(raw, 0)

    def represent(self):
        ext_str = ''
        for ext in self.extensions:
            ext_str += ext.represent(2)

        return "Handshake-encrypted_extensions:\n"       \
             + "  Extensions:\n" + ext_str
