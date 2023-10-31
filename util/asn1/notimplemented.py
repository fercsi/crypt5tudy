#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Asn1NotImplemented(Asn1Object):
    _type_name = 'NOT IMPLEMENTED'
    data: bytes

    def to_ber(self):
        if self._constructed or self._encapsulated:
            return super().to_ber()
        return self.data

    def from_ber(self, raw: bytes):
        self.data = raw
        super().from_ber(raw)

    def _repr_content(self, level: int):
        class_str = ['Universal', 'Application', 'Context-specific', 'Private'][self._class]
        const_str = ['Primitive','Constructed'][self._constructed]
        text = '\n'
        text += '  ' * (level + 1) + f'Class = {class_str}\n'
        text += '  ' * (level + 1) + f'P/C = {const_str}\n'
        text += '  ' * (level + 1) + f'Type = {self._type_id}\n'
        text += '  ' * (level + 1) + f'Content ='
        if self._constructed or self._encapsulated:
            return text + super()._repr_content(level + 1)
        return text + self.format_data('hex_block', self.data, level + 2)
