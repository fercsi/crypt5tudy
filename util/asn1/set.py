#!/usr/bin/python3

from .object import Asn1Object

class Asn1Set(Asn1Object):
    _type_id = 17
    _type_name = 'SET'
    _constructed = True
