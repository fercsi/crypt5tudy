#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Asn1String(Asn1Object):

    def __init__(self, text: str = '', *, constructed: bool = False):
        super().__init__()
        self._constructed = constructed
        self.data = text.encode()

    @property
    def value(self):
        return self.data.decode(self._default_format[4:], errors='replace')

    @value.setter
    def value(self, text: str):
        # Intentionally raise error if encoding fails
        self.data = text.encode(self._default_format[4:])

    def to_ber(self):
        if self._constructed or self._encapsulated:
            return super().to_ber()
        return self.data

    def from_ber(self, raw: bytes):
        if not super().from_ber(raw):
            self.data = raw

    def _repr_content(self, level: int):
        if self._constructed or self._encapsulated:
            return super()._repr_content(level)
        return self.format_data(self.data, level + 1)

class Asn1Utf8String(Asn1String):
    _type_id = 12
    _type_name = 'UTF8 STRING'
    _default_format = 'str_utf8'

class Asn1PrintableString(Asn1String):
    _type_id = 19
    _type_name = 'PRINTABLE STRING'
    _default_format = 'str_ascii'

class Asn1IA5String(Asn1String):
    _type_id = 22
    _type_name = 'IA5 STRING'
    _default_format = 'str_ascii'
