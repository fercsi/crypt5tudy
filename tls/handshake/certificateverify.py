#!/usr/bin/python3
# RFC8446

from .handshake import Handshake
from ..extension.signaturealgorithms import ALGORITHM_IDS
from util.serialize import *

class CertificateVerify(Handshake):
    def __init__(self, algorithm: int|str = 0):
        super().__init__()
        self.handshake_type = 15
        self.set_algorithm(algorithm)
        self.signature = b''

    def set_algorithm(self, algorithm: int|str) -> None:
        if isinstance(algorithm, str):
            algorithm = ALGORITHM_IDS.get(algorithm.lower())
            if algorithm is None:
                raise NotImplementedError("Signature algorithm not supported")
        self.algorithm = algorithm

    def pack_handshake_content(self):
        algorithm = pack_u16(self.algorithm)
        signature = pack_bytes(self.signature, 2)
        return algorithm + signature

    def unpack_handshake_content(self, raw):
        pos = 0
        self.algorithm = unpack_u16(raw, pos)
        pos += 2
        self.signature = unpack_bytes(raw, pos, 2)

    def represent(self, level: int = 0):
        algorithm = None
        for name, id in ALGORITHM_IDS.items():
            if id == self.algorithm:
                algorithm = name
                break
        if algorithm is None:
            algorithm = f'unknown_{self.algorithm:0>4x}'
        signature = self.signature.hex()
        return "Handshake-certificate_verify:\n"       \
             + f"  Algorithm: {algorithm}\n" \
             + f"  Signature: {signature}\n"
