#!/usr/bin/python3
# RFC8446

from util.serialize import *
from util.random import random_bytes
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
    def __init__(self, cipher_suite: list|None = None):
        super().__init__()
        self.message_tlsversion = 0x0301 # for rooter compatibility reasons!
        self.handshake_type = 1
        self.client_hello_tlsversion = 0x0303
        self.random = random_bytes(32)
        # Session ID is not used in TLS1.3, but for security reasons don't leak
        # information:
        self.session_id = pack_bytes(random_bytes(32), 1)
        self.cipher_suite = []
        if cipher_suite:
            self.add_cipher_suite(cipher_suite)
        self.compression = [0] # TLS1.3 does not allow compression

    def add_cipher_suite(self, cipher_suite: str|int|list) -> None:
        if not isinstance(cipher_suite, list):
            cipher_suite = [cipher_suite]
        cipher_suite = (CS_IDS[g.replace('-', '_').upper()]
                if isinstance(g, str) else g for g in cipher_suite)
        self.cipher_suite.extend(cipher_suite)

    def pack_handshake_content(self):
        tlsver = pack_u16(self.client_hello_tlsversion)
        cip_suite = pack_u16_list(self.cipher_suite, 2)
        cmprss = pack_u8_list(self.compression, 1)
        exts = self.pack_extensions()
        packed = tlsver + self.random + self.session_id + cip_suite + cmprss + exts
        return packed

    def unpack_handshake_content(self, raw):
        pos = 0
        self.client_hello_tlsversion = unpack_u16(raw, pos)
        pos += 2
        self.random = raw[pos:pos+31]
        pos += 32
        self.session_id = unpack_bytes(raw, pos, 1)
        pos += 1 + len(self.session_id)
        self.cipher_suite = unpack_u16_list(raw, pos, 2)
        pos += 2 + len(self.cipher_suite) * 2
        self.compression = unpack_u8_list(raw, pos, 1)
        pos += 1 + len(self.compression)
#>        rawexts = unpack_bytes(raw, pos, 2)
        self.unpack_extensions(raw, pos)

    def represent(self):
        random_str = self.random.hex() + "\n"
        session_str = self.session_id.hex() + "\n"
        revlut = {}
        for k, v in CS_IDS.items():
            revlut[v] = k
        cipsuite_str = ""
        for cs in self.cipher_suite:
            cstxt = revlut.get(cs) or f'unknown cipher suite {cs:0>4x}'
            cipsuite_str += f"    - {cstxt}\n" 
        cmprss_str = ""
        for c in self.compression:
            cmprss_str += "    - " \
                + ("uncompressed" if c == 0 else "unknown_{c:0>2x}") + "\n"
        ext_str = ''
        for ext in self.extensions:
            ext_str += ext.represent(2)

        return "Handshake-client_hello:\n"       \
             + "  Random: " + random_str           \
             + "  SessionID: " + session_str      \
             + "  CipherSuite:\n" + cipsuite_str \
             + "  Compression:\n" + cmprss_str     \
             + "  Extensions:\n" + ext_str

    def __str__(self) -> str:
        return self.represent()
