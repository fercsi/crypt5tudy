#!/usr/bin/python3
# RFC8446

from .handshake import Handshake
from ..extension.signaturealgorithms import ALGORITHM_IDS
from ..util import *

class CertificateVerify(Handshake):
    def __init__(self, algorithm: int|str = 0):
        super().__init__()
        self.handshakeType = 15
        self.setAlgorithm(algorithm)
        self.signature = b''

    def setAlgorithm(self, algorithm: int|str) -> None:
        if isinstance(algorithm, str):
            algorithm = ALGORITHM_IDS.get(algorithm.lower())
            if algorithm is None:
                raise NotImplementedError("Signature algorithm not supported")
        self.algorithm = algorithm

    def packHandshakeContent(self):
        algorithm = packU16(self.algorithm)
        signature = packBytes(self.signature, 2)
        return algorithm + signature

    def unpackHandshakeContent(self, raw):
        pos = 0
        self.algorithm = unpackU16(raw, pos)
        pos += 2
        self.signature = unpackBytes(raw, pos, 2)

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
