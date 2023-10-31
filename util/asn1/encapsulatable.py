#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Encapsulatable:
    def encapsulate(self, asn1_object: Asn1Object):
        if self._type_name[-1] != ')':
            self._type_name += ' (encapsulated)'
        if self.content is None:
            self.content = []
        self.content.append(asn1_object)

    def process_encapsulated(self, raw: bytes|None = None):
        from .asn1 import Asn1
        if self._type_name[-1] != ')':
            self._type_name += ' (encapsulated)'
        self.content = []
        raw = raw or self._raw
        pos = 0
        endpos = len(raw)
        while pos < endpos:
            obj, pos = Asn1._from_ber(raw, pos)
            self.content.append(obj)
