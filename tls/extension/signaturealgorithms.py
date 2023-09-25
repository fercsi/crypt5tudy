#!/usr/bin/python3
# RFC8446

from .util import *
from .extension import Extension

ALGORITHM_IDS: dict[str, int] = {
        # "RSA-PKCS1-SHA256" form can be used, too
    # RSASSA-PKCS1-v1_5 algorithms
    'rsa_pkcs1_sha256': 0x0401,
    'rsa_pkcs1_sha384': 0x0501,
    'rsa_pkcs1_sha512': 0x0601,

    # ECDSA algorithms
    'ecdsa_secp256r1_sha256': 0x0403,
    'ecdsa_secp384r1_sha384': 0x0503,
    'ecdsa_secp521r1_sha512': 0x0603,

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    'rsa_pss_rsae_sha256': 0x0804,
    'rsa_pss_rsae_sha384': 0x0805,
    'rsa_pss_rsae_sha512': 0x0806,

    # EdDSA algorithms
    'ed25519': 0x0807,
    'ed448': 0x0808,

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    'rsa_pss_pss_sha256': 0x0809,
    'rsa_pss_pss_sha384': 0x080a,
    'rsa_pss_pss_sha512': 0x080b,

    # Legacy algorithms
    'rsa_pkcs1_sha1': 0x0201,
    'ecdsa_sha1': 0x0203,
    }

class SignatureAlgorithms(Extension):
    def __init__(self, algorithms: list[str|int]|None = None):
        super().__init__()
        self.extensionType = 13
#>        self.algorithms = list(ALGORITHM_IDS.values())
        self.algorithms = []
        if algorithms:
            self.add(algorithms)

    def add(self, algorithm: str|int|list) -> None:
        if not isinstance(algorithm, list):
            algorithm = [algorithm]
        algorithm = (ALGORITHM_IDS[g.replace('-', '_').lower()]
                if isinstance(g, str) else g for g in algorithm)
        self.algorithms.extend(algorithm)

    def packExtensionContent(self):
        return packU16List(self.algorithms, 2)
