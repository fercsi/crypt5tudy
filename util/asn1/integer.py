#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object

class Asn1Integer(Asn1Object):
    _type_id = 2
    _type_name = 'INTEGER'

    _default_format = 'dec'
    value: int = 0
    length: int|None = None

    def __init__(self, value: int = 0, length: int|None = None):
        super().__init__()
        self.value = int(value)
        self.length = length

    def __int__(self):
        return self.value

    def to_ber(self):
        return pack_int(self.value, self.length)

    def from_ber(self, raw: bytes):
        self.value = unpack_int(raw, 0, len(raw))
        self.length = len(raw)

    def _repr_content(self, level: int):
        if self.format == 'dec':
            return str(self.value)
        return self.format_data(self.to_ber(), level + 1)
