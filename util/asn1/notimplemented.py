#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Asn1NotImplemented(Asn1Object):
    _type_name = 'NOT IMPLEMENTED'
    content: bytes

    def to_ber(self):
        return self.content

    def from_ber(self, raw: bytes):
        self.content = raw

    def _repr_content(self, level: int):
        return f'{self._type_id}, ' + self.content.hex()
