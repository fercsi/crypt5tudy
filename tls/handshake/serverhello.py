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

class ServerHello(Handshake):
    def __init__(self, cipherSuite: int = 0):
        super().__init__()
        self.handshakeType = 1
        self.serverHelloTLSVersion = 0x0303
        self.random = randomBytes(32)
        # Session ID is not used in TLS1.3, but for security reasons don't leak
        # information:
        self.sessionId = packBytes(randomBytes(32), 1)
        self.cipherSuite = cipherSuite
        self.compression = 0 # TLS1.3 does not allow compression

    def addCipherSuite(self, cipherSuite: str|int|list) -> None:
        if not isinstance(cipherSuite, list):
            cipherSuite = [cipherSuite]
        cipherSuite = (CS_IDS[g.replace('-', '_').upper()]
                if isinstance(g, str) else g for g in cipherSuite)
        self.cipherSuite.extend(cipherSuite)

    def packHandshakeContent(self):
        tlsver = packU16(self.serverHelloTLSVersion)
        cipSuite = packU16(self.cipherSuite)
        cmprss = packU8(self.compression)
        exts = self.packExtensions()
        packed = tlsver + self.random + self.sessionId + cipSuite + cmprss + exts
        return packed

    def unpackHandshakeContent(self, raw):
        pos = 0
        self.serverHelloTLSVersion = unpackU16(raw, pos)
        pos += 2
        self.random = raw[pos:pos+31]
        pos += 32
        self.sessionId = unpackBytes(raw, pos, 1)
        pos += 1 + len(self.sessionId)
        self.cipherSuite = unpackU16(raw, pos)
        pos += 2
        self.compression = unpackU8(raw, pos)
        pos += 1
        rawexts = unpackBytes(raw, pos, 2)
        self.unpackExtensions(rawexts)

    def represent(self):
        randomStr = self.random.hex()
        sessionStr = self.sessionId.hex()

        revlut = {}
        for k, v in CS_IDS.items():
            revlut[v] = k
        cs = self.cipherSuite
        cipsuiteStr = revlut.get(cs) or f'unknown_{cs:0>4x}'

        cm = self.compression
        cmprssStr = "uncompressed" if cm == 0 else "unknown_{c:0>2x}"

        extStr = ''
        for ext in self.extensions:
            extStr += ext.represent(2)

        return "Handshake - server_hello\n"       \
             + f"  Random: {randomStr}\n"         \
             + f"  SessionID: {sessionStr}\n"     \
             + f"  CipherSuite: {cipsuiteStr}\n"  \
             + f"  Compression: {cmprssStr}\n"    \
             + "  Extensions:\n" + extStr
