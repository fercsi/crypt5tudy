#!/usr/bin/python3
# RFC8446

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

HELLORETRYREQUEST_HASH = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')

class ServerHello(Handshake):
    def __init__(self, cipher_suite: int = 0):
        super().__init__()
        self.handshake_type = 1
        self.server_hello_tlsversion = 0x0303
        self.random = random_bytes(32)
        # NOTE: In the spirit of "downgrade protection", negotiating TLS1.2
        # random must end with b'DOWNGRD\1'. Support for <TLS1.2 won't ever
        # be part of this tool (for more info, see RFC8446 4.1.3)

        # Session ID is not used in TLS1.3, but for security reasons don't leak
        # information:
        self.session_id = pack_bytes(random_bytes(32), 1)
        self.cipher_suite = cipher_suite
        self.compression = 0 # TLS1.3 does not allow compression
        self.hello_retry_request = False

    def add_cipher_suite(self, cipher_suite: str|int|list) -> None:
        if not isinstance(cipher_suite, list):
            cipher_suite = [cipher_suite]
        cipher_suite = (CS_IDS[g.replace('-', '_').upper()]
                if isinstance(g, str) else g for g in cipher_suite)
        self.cipher_suite.extend(cipher_suite)

    def pack_handshake_content(self):
        tlsver = pack_u16(self.server_hello_tlsversion)
        cip_suite = pack_u16(self.cipher_suite)
        cmprss = pack_u8(self.compression)
        exts = self.pack_extensions()
        packed = tlsver + self.random + self.session_id + cip_suite + cmprss + exts
        return packed

    def unpack_handshake_content(self, raw):
        pos = 0
        self.server_hello_tlsversion = unpack_u16(raw, pos)
        pos += 2
        self.random = raw[pos:pos+31]
        if self.random == HELLORETRYREQUEST_HASH:
            self.hello_retry_request = True
        pos += 32
        self.session_id = unpack_bytes(raw, pos, 1)
        pos += 1 + len(self.session_id)
        self.cipher_suite = unpack_u16(raw, pos)
        pos += 2
        self.compression = unpack_u8(raw, pos)
        pos += 1
#>        rawexts = unpack_bytes(raw, pos, 2)
        self.unpack_extensions(raw, pos)

    def represent(self):
        random_str = self.random.hex()
        session_str = self.session_id.hex()

        revlut = {}
        for k, v in CS_IDS.items():
            revlut[v] = k
        cs = self.cipher_suite
        cipsuite_str = revlut.get(cs) or f'unknown_{cs:0>4x}'

        cm = self.compression
        cmprss_str = "uncompressed" if cm == 0 else "unknown_{c:0>2x}"

        ext_str = ''
        for ext in self.extensions:
            ext_str += ext.represent(2)

        return "Handshake-server_hello:\n"       \
             + f"  Random: {random_str}\n"         \
             + f"  SessionID: {session_str}\n"     \
             + f"  CipherSuite: {cipsuite_str}\n"  \
             + f"  Compression: {cmprss_str}\n"    \
             + "  Extensions:\n" + ext_str


class HelloRetryRequest(ServerHello):
    def __init__(self):
        super().__init__()
        # RFC8446 4.1.3
        # Note: random should be sha256 hash of "HelloRetryRequest"
        self.random = HELLORETRYREQUEST_HASH
        self.hello_retry_request = True
