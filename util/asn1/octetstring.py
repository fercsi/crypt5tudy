#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object

class Asn1OctetString(Asn1Object):
    _type_id = 4
    _type_name = 'OCTET STRING'

    _default_format: str = 'hex_block'
    data: bytearray

    def __init__(self):
        super().__init__()
        self.data = bytearray()

    def __bytes__(self):
        return self.data

    def __getitem__(self, index: int|range):
        length = len(self.data)
        if isinstance(index, int):
            if index >= length:
                return 0
            return self.data[index]
        if isinstance(index, slice):
            start = index.start
            stop = index.stop
            step = index.step or 1
            if start is None:
                if step < 0:
                    start = length - 1
                else:
                    start = 0
            elif start < 0:
                start += length
            if stop is None:
                if step < 0:
                    stop = -1
                else:
                    stop = length
            elif stop < 0:
                stop += self.length
            chunk = self.data[start:length:step]
            if stop > length:
                chunk += b'\0' * (stop - length)
            return chunk
        raise TypeError('Asn1BitString indices must be integers or slices')

#>    def __setitem__(self, index: int|range, value: int):
#>        if isinstance(index, int):
#>            if index < -self.length:
#>                raise IndexError('index out of range')
#>            if index >= self.length:
#>                self.set_length(index + 1)
#>            if index < 0:
#>                index = self.length - index
#>            mask = 1 << (~index & 7)
#>            if value:
#>                self.bits[index >> 3] |= mask
#>            else:
#>                self.bits[index >> 3] &= ~mask
#>            return
#>        if isinstance(index, slice):
#>            NotImplemented # TODO 
#>        raise TypeError('Asn1BitString indices must be integers or slices')
#>
#>    def set_length(self, length) -> None:
#>        if length < self.length:
#>            bitlen = length + 7 >> 3
#>            self.bits = self.bits[:bitlen]
#>            self.bits[-1] &= ~((1 << (-length & 7)) - 1)
#>        elif length > self.length:
#>            add = (length + 7 >> 3) - len(self.bits)
#>            self.bits += b'\0' * add
#>        self.length = length

    def to_ber(self):
        if self._constructed or self._encapsulated:
            return super().to_ber()
        return self.data

    def from_ber(self, raw: bytes):
        if not super().from_ber(raw):
            self.data = bytearray(raw)
