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

    def unpackHandshakeContent(self, raw):
        pos = 0
        self.clientHelloTLSVersion = unpackU16(raw, pos)
        pos += 2
        self.random = raw[pos:pos+31]
        pos += 32
        self.sessionId = unpackBytes(raw, pos, 1)
        pos += 1 + len(self.sessionId)
        self.cipherSuite = unpackU16List(raw, pos, 2)
        pos += 2 + len(self.cipherSuite) * 2
        self.compression = unpackU8List(raw, pos, 1)
        pos += 1 + len(self.compression)
        rawexts = unpackBytes(raw, pos, 2)
        self.unpackExtensions(rawexts)

    def represent(self):
        randomStr = self.random.hex() + "\n"
        sessionStr = self.sessionId.hex() + "\n"
        revlut = {}
        for k, v in CS_IDS.items():
            revlut[v] = k
        cipsuiteStr = ""
        for cs in self.cipherSuite:
            cstxt = revlut.get(cs) or f'unknown cipher suite {cs:0>4x}'
            cipsuiteStr += f"    - {cstxt}\n" 
        cmprssStr = ""
        for c in self.compression:
            cmprssStr += "    - " \
                + ("uncompressed" if c == 0 else "unknown_{c:0>2x}") + "\n"
        extStr = ''
        for ext in self.extensions:
            extStr += ext.represent(2)
        return "Handshake - client_hello\n"       \
             + "  Random: " + randomStr           \
             + "  SessionID: " + sessionStr      \
             + "  CipherSuite:\n" + cipsuiteStr \
             + "  Compression:\n" + cmprssStr     \
             + "  Extensions:\n" + extStr

    def __str__(self) -> str:
        return self.represent()
