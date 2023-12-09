#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .objects import *

_TYPE_HANDLERS = {
     0: Asn1Eoc,
     1: Asn1Boolean,
     2: Asn1Integer,
     3: Asn1BitString,
     4: Asn1OctetString,
     5: Asn1Null,
     6: Asn1ObjectIdentifier,
     8: Asn1External,
    12: Asn1Utf8String,
    16: Asn1Sequence,
    17: Asn1Set,
    19: Asn1PrintableString,
    22: Asn1IA5String,
    23: Asn1UtcTime,
}

class Asn1:
    @staticmethod
    def to_ber(asn1_object: Asn1Object) -> bytes:
        content = asn1_object.to_ber()
        asn1_byte1 = asn1_object._type_id
        asn1_byte2 = None
        if asn1_byte1 > 0x30:
            asn1_byte2 = ans1_byte1
            ans1_byte1 = 0x31
        asn1_byte1 |= asn1_object._constructed << 5
        asn1_byte1 |= asn1_object._class << 6
        asn1_type = pack_u8(asn1_byte1)
        if asn1_byte2 is not None:
            asn1_type += pack_u8(asn1_byte2)
        length = len(content)
        if length < 0x80:
            raw_len = pack_u8(length)
        else:
            raw_len = pack_uint(length)
            raw_len = pack_u8(0x80 + len(raw_len)) + raw_len
        return asn1_type + raw_len + content

    @staticmethod
    def from_ber(raw: bytes):
        return Asn1._from_ber(raw, 0)[0]

    @staticmethod
    def _from_ber(raw: bytes, pos: int = 0):
        asn1_type = raw[pos]
        spos = pos
        pos += 1
        constructed = (asn1_type & 0x20) != 0
        type_class = asn1_type >> 6
        asn1_type &= 0x1f
        if asn1_type == 0x1f:
            asn1_type = raw[pos]
            pos += 1
        length = raw[pos]
        pos += 1
        if length & 0x80:
            ll = length & 0x7f
            length = unpack_uint(raw, pos, ll)
            pos += ll
        data = raw[pos:pos+length]
        pos += length
        content = Asn1._process_type(asn1_type, constructed, type_class, data, raw[spos:pos])
        return content, pos

    @staticmethod
    def _process_type(asn1_type: int, constructed: bool, type_class: int, data: bytes, ber: bytes):
        # TODO: understand Context-specific behaviour. e.g. EOC
#>        if type_class & 1: # class 0, 2 fall through
        if type_class != 0: # class 0, 2 fall through
            type_handler = Asn1NotImplemented
        else:
            type_handler = _TYPE_HANDLERS.get(asn1_type, Asn1NotImplemented)
        content = type_handler()
        content._type_id = asn1_type
        content._constructed = constructed
        content._class = type_class
        content._raw = data
        content._ber = ber
        content.from_ber(data)
        return content
