#!/usr/bin/python3
# RFC8446

from tls.util import *
from .handshake import Handshake

class Finished(Handshake):
    def __init__(self, verifyData: bytes = b''):
        super().__init__()
        self.handshakeType = 20
        self.verifyData = verifyData

    def packHandshakeContent(self):
        return self.verifyData

    def unpackHandshakeContent(self, raw):
        self.verifyData = raw

    def represent(self):
        verifyData = self.verifyData.hex()
        return "Handshake-finished:\n"       \
             + f"  VerifyData: {verifyData}\n"
