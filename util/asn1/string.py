#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Asn1String(Asn1Object):
    value: str = ''

    def __init__(self, value: str = ''):
        super().__init__()
        self.value = value

    def to_ber(self):
        return self.value.encode()

    def from_ber(self, raw: bytes):
        self.value = raw.decode()

    def _repr_content(self, level: int):
        return repr(self.value)

class Asn1Utf8String(Asn1String):
    _type_id = 12
    _type_name = 'UTF8 STRING'

class Asn1PrintableString(Asn1String):
    _type_id = 19
    _type_name = 'PRINTABLE STRING'
