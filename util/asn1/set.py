#!/usr/bin/python3

from .sequence import Asn1Sequence

class Asn1Set(Asn1Sequence):
    _type_id = 17
    _type_name = 'SET'

