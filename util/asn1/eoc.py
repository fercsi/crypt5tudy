#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from .object import Asn1Object

class Asn1Eoc(Asn1Object):
    _type_id = 0
    _type_name = 'EOC'
