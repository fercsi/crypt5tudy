#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object

class Asn1Integer(Asn1Object):
    _type_id = 2
    _type_name = 'INTEGER'

    value: int = 0
    length: int|None = None
    display_mode: str = 'dec' # 'hex',

    def __init__(self, value: int = 0, length: int|None = None):
        self.value = int(value)
        self.length = length

    def __int__(self):
        return self.value

    def annotate(self, name: str|None, display_mode: str|None = None):
        self.name = name
        self.display_mode = display_mode or 'dec'

    def to_ber(self):
        return pack_int(self.value, self.length)

    def from_ber(self, raw: bytes):
        self.value = unpack_int(raw, 0, len(raw))
        self.length = len(raw)

    def _repr_content(self, level: int):
        if self.display_mode == 'hex':
            if self.length:
                return ('{:0>' + str(self.length * 2) + 'x}').format(self.value)
            h = hex(self.value)
            if len(h) & 1:
                h = '0' + h
            return h
        elif self.display_mode == 'block':
            text = '\n'
            byte_form = self.to_ber()
            for i in range(0, len(byte_form), 16):
                text += '  ' * level + '  ' + ' '.join(f'{b:0>2x}' for b in byte_form[i:i+16]) + '\n'
            return text[:-1]
        else:
            return str(self.value)
