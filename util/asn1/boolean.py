#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Asn1Boolean(Asn1Object):
    _type_id = 1
    _type_name = 'BOOLEAN'

    value: bool = False

    def __init__(self, value: bool = False):
        self.value = True if value else False

    def __bool__(self):
        return self.value

    def to_ber(self):
        return b'\xff' if self.value else b'\0'

    def from_ber(self, raw: bytes):
        self.value = raw[0] > 0

    def _repr_content(self, level: int):
        return 'true' if self.value else 'false'
