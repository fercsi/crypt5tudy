#!/usr/bin/python3

from typing import NamedTuple

class CipherSuite(NamedTuple):
    number: int
    idstr: str
    kex: str|None
    signature: str|None
    encryption: str
    hash: str
    kLen: int # in octets
    nMin: int
    nMax: int

CIPHER_SUITE_BY_ID = {
    0x1301: CipherSuite( # RFC5116
        0x1301, 'TLS_AES_128_GCM_SHA256',
        None, None,
        'AES_GCM_13', 'SHA256',
        16, 12, 12,
    ),
    0x1302: CipherSuite( # RFC5116
        0x1302, 'TLS_AES_256_GCM_SHA384',
        None, None,
        'AES_GCM_13', 'SHA384',
        32, 12, 12,
    ),
    0x1303: CipherSuite( #RFC7539
        0x1303, 'TLS_CHACHA20_POLY1305_SHA256',
        None, None,
        'CHACHA20_POLY1305_13', 'SHA256',
        256, 12, 12,
    ),
    0x1304: CipherSuite( # RFC5116
        0x1304, 'TLS_AES_128_CCM_SHA256',
        None, None,
        'AES_128_CCM_16_13', 'SHA256',
        16, 12, 12,
    ),
    0x1305: CipherSuite( # RFC5116
        0x1305, 'TLS_AES_128_CCM_8_SHA256',
        None, None,
        'AES_128_CCM_8_13', 'SHA256',
        16, 12, 12,
    ),
}

CIPHER_SUIT_BY_NAME = {}
for id, cs in CIPHER_SUITE_BY_ID.items():
    CIPHER_SUIT_BY_NAME[cs.idstr] = cs

