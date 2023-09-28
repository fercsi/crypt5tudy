#!/usr/bin/python3
# RFC8446

import hashlib
import random
from tls.util import *
from .handshake import Handshake

CS_IDS = {
    'TLS_AES_128_GCM_SHA256':            0x1301,
    'TLS_AES_256_GCM_SHA384':            0x1302,
    'TLS_CHACHA20_POLY1305_SHA256':      0x1303,
    'TLS_AES_128_CCM_SHA256':            0x1304,
    'TLS_AES_128_CCM_8_SHA256':          0x1305,

    'TLS_EMPTY_RENEGOTIATION_INFO_SCSV': 0x00ff,
    }

class ClientHello(Handshake):
    def __init__(self, cipherSuite: list|None = None):
        super().__init__()
        self.handshakeType = 1
        self.clientHelloTLSVersion = 0x0303
        self.random = randomBytes(32)
        # Session ID is not used in TLS1.3, but for security reasons don't leak
        # information:
        self.sessionId = packBytes(randomBytes(32), 1)
        self.cipherSuite = []
        if cipherSuite:
            self.addCipherSuite(cipherSuite)
        self.compression = [0] # TLS1.3 does not allow compression

    def addCipherSuite(self, cipherSuite: str|int|list) -> None:
        if not isinstance(cipherSuite, list):
            cipherSuite = [cipherSuite]
        cipherSuite = (CS_IDS[g.replace('-', '_').upper()]
                if isinstance(g, str) else g for g in cipherSuite)
        self.cipherSuite.extend(cipherSuite)

    def packHandshakeContent(self):
        tlsver = packU16(self.clientHelloTLSVersion)
        cipSuite = packU16List(self.cipherSuite, 2)
        cmprss = packU8List(self.compression, 1)
        exts = self.packExtensions()
        packed = tlsver + self.random + self.sessionId + cipSuite + cmprss + exts
        return packed

    def str(self):
        randomStr = "    " + self.random.hex() + "\n"
        sessionStr = "    " + self.sessionId.hex() + "\n"
        cipsuiteStr = "    " + ', '.join(f'{n:0>4x}' for n in self.cipherSuite) + "\n"
        cmprssStr = "    " + ', '.join(f'{n:0>4x}' for n in self.compression) + "\n"
        extStr = "    -\n"
        return "Handshake - client_hello\n"       \
             + "  random:\n" + randomStr          \
             + "  session ID:\n" + sessionStr     \
             + "  cipher suites:\n" + cipsuiteStr \
             + "  compressions:\n" + cmprssStr    \
             + "  extensions:\n" + extStr

    def __str__(self) -> str:
        return self.str()
