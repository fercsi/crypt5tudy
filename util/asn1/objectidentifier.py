#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from util.objectidref import OBJECT_ID_REFERENCE
from .object import Asn1Object

class Asn1ObjectIdentifier(Asn1Object):
    _type_id = 6
    _type_name = 'OBJECT IDENTIFIER'

    arcs: list[int]

    def __init__(self, arcs: list[int] = []):
        self.arcs = arcs

    def to_ber(self):
        if not self.arcs:
            return b''
        b0 = self.arcs[0] * 40
        if len(self.arcs) == 1:
            return b0
        b0 += self.arcs[1]
        text = pack_u8(b0)
        for arc in self.arcs[2:]:
#>            print('!',arc)
            parts = []
            if arc:
                parts = []
                while arc:
                    parts.append(arc & 0x7f)
                    arc >>= 7
            else:
                parts = [0]
            parts = parts[:1] + [0x80|b for b in parts[1:]]
            text += bytes(reversed(parts))
        return text

    def from_ber(self, raw: bytes):
        if not raw:
            self.arcs = []
            return
        self.arcs = list(divmod(raw[0], 40))
        pos = 1
        endpos = len(raw)
        while pos < endpos:
            arc = 0
            part = raw[pos]
            pos += 1
            while part & 0x80:
                arc |= part & 0x7f
                arc <<= 7
                part = raw[pos]
                pos += 1
            arc |= part
            self.arcs.append(arc)

    def _repr_content(self, level: int):
        objid = '.'.join(str(a) for a in self.arcs)
        name = OBJECT_ID_REFERENCE.get(objid, None)
        if name is not None:
            objid += f' ({name})'
        return objid
