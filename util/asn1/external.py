#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object

class Asn1External(Asn1Object):
    _type_id = 8
    _type_name = 'EXTERNAL'
    _constructed = True
