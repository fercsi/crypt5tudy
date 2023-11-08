#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object

class Asn1Integer(Asn1Object):
    _type_id = 2
    _type_name = 'INTEGER'

    _default_format = 'auto'
    value: int = 0
    length: int|None = None

    def __init__(self, value: int = 0, length: int|None = None):
        super().__init__()
        self.value = int(value)
        self.length = length

    def __int__(self):
        return self.value

    def to_ber(self):
        return pack_sint(self.value, self.length)

    def from_ber(self, raw: bytes):
        self.value = unpack_sint(raw, 0, len(raw))
        self.length = len(raw)

    def _repr_content(self, level: int):
        # In contrast to other types values are treated as signed
        if self.format == 'auto':
            if self.value == 0:
                return '0'
            format = 'dec_hex' if self.value.bit_length() <= 64 else 'hex_block'
        else:
            format = self.format
        if format == 'dec':
            return str(self.value)
        if format == 'hex':
            return hex(self.value)
        if format == 'dec_hex':
            return f'{self.value} ({hex(self.value)})'
        if format == 'bin':
            return bin(self.value)
        return self.format_data(self.to_ber(), level + 1, format=format)
