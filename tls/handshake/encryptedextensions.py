#!/usr/bin/python3
# RFC8446

from tls.util import *
from .handshake import Handshake

class EncryptedExtensions(Handshake):
    def __init__(self, cipherSuite: list|None = None):
        super().__init__()
        self.handshakeType = 8
        self.encryptedExtensionsTLSVersion = 0x0303

    def packHandshakeContent(self):
        exts = self.packExtensions()
        return exts

    def unpackHandshakeContent(self, raw):
        self.unpackExtensions(raw, 0)

    def represent(self):
        extStr = ''
        for ext in self.extensions:
            extStr += ext.represent(2)

        return "Handshake-encrypted_extensions:\n"       \
             + "  Extensions:\n" + extStr
