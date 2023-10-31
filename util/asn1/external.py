#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object
from .constructable import Constructable
from .encapsulatable import Encapsulatable

class Asn1External(Constructable, Encapsulatable, Asn1Object):
    # TODO: constructed
    _type_id = 8
    _type_name = 'EXTERNAL'

    data: bytearray
#>    content: list[Asn1Object]|None = None

    def __init__(self):
        self.data = bytearray()

    def __bytes__(self):
        return self.data

#>    def annotate(self, name: str|None, attributes = None):
#>        """Annotates either bits or an encapsulated object
#>
#>        attributes types:
#>        - content (if content is encapsulated)
#>        - display_mode (if not)
#>        """
#>        if self.content is not None:
#>            return super().annotate(name, attributes)
#>        self.name = name

    def to_ber(self):
#>        if self.content is not None:
#>            return super().to_ber()
        return self.data

    def from_ber(self, raw: bytes):
        self.data = bytearray(raw)

    def _repr_content(self, level: int):
#>        if self.content is not None:
#>            return super()._repr_content(level)
        text = '\n'
        byte_form = self.to_ber()
        for i in range(0, len(byte_form), 16):
            text += '  ' * level + '  ' + ' '.join(f'{b:0>2x}' for b in byte_form[i:i+16]) + '\n'
        return text[:-1]
