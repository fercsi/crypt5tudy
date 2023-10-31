#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object
from .constructable import Constructable

class Asn1Sequence(Constructable, Asn1Object):
    _type_id = 16
    _type_name = 'SEQUENCE'
    _constructable = True
