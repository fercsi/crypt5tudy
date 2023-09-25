#!/usr/bin/python3
# RFC8446

from .util import *
from .handshake import Handshake

class ServerHello(Handshake):
    def __init__(self, *,
            cyperSuite: int,
            compression: int,
            sessionId: bytes|None = None
            ):
        super().__init__()
        self.handshakeType = 2
        self.clientHelloTLSVersion = 0x0303
        self.random = randomBytes(32)
        if sessionId is None:
            # Session ID is not used in TLS1.3, but for security reasons don't
            # leak information:
            self.sessionId = packBytes(randomBytes(32), 1)
        else:
            self.sessionId = sessionId
        self.cypherSuite = cypherSuite
        self.compression = compression

    def packHandshakeContent(self):
#>        tlsver = self.clientHelloTLSVersion.to_bytes(2, 'big')
        tlsver = packU16(self.clientHelloTLSVersion)
        cypSuite = packU16(self.cypherSuite)
        cmprss = packU8(self.compression)
        exts = self.packExtensions()
        packed = tlsver + self.random + self.sessionId + cypSuite + cmprss + exts
#>        packed = type + length + content
        return packed
