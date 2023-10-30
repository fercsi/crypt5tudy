#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Asn1Null(Asn1Object):
    _type_id = 5
    _type_name = 'NULL'

    def __init__(self, bits: bytes = b''):
        self.bits = bits

    def to_ber(self):
        return b''

    def from_ber(self, raw: bytes):
        pass

    def _repr_content(self, level: int):
        return '~'
