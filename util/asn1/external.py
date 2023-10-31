#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object

class Asn1External(Asn1Object):
    # TODO: constructed
    _type_id = 8
    _type_name = 'EXTERNAL'
    _constructed = True

    data: bytearray

    def __init__(self):
        super().__init__()
        self.data = bytearray()

    def __bytes__(self):
        return self.data

    def to_ber(self):
        if self._constructed or self._encapsulated:
            return super().to_ber()
        return self.data

    def from_ber(self, raw: bytes):
        self.data = bytearray(raw)

    def _repr_content(self, level: int):
        if self._constructed or self._encapsulated:
            return super()._repr_content(level)
        return self.format_data('hex_block', self.data, level + 1)
