#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Constructable: # mixin class
    content: list[Asn1Object]

    def __init__(self):
        self.content = []

    def append(self, asn1_object: Asn1Object):
        self.content.append(asn1_object)

    def annotate(self, name: str|None, content: list[tuple]|None = None):
        self.name = name
        if content is not None:
            for item, ann in zip(self.content, content):
                item.annotate(*ann)

    def to_ber(self):
        from .asn1 import Asn1
        content = b''
        for asn1_object in self.content:
            content += Asn1.to_ber(asn1_object)
        return content

    def from_ber(self, raw: bytes):
        from .asn1 import Asn1
        pos = 0
        self.content = []
        while pos < len(raw):
            asn1_object, pos = Asn1._from_ber(raw, pos)
            self.append(asn1_object)

    def _repr_content(self, level: int):
        text = '\n'
        for asn1_object in self.content:
            text += asn1_object._represent(level + 1)
        return text[:-1]
