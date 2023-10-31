#!/usr/bin/python3

from .object import Asn1Object
from .constructable import Constructable

class Asn1Set(Constructable, Asn1Object):
    _type_id = 17
    _type_name = 'SET'
    _constructable = True
