#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

import itertools
from util.serialize import *
from .object import Asn1Object

class Asn1OctetString(Asn1Object):
    _type_id = 4
    _type_name = 'OCTET STRING'

    _default_format: str = 'hex_block'
    data: bytearray

    def __init__(self, data: bytes = b'', *, constructed: bool = False):
        super().__init__()
        self._constructed = constructed
        self.data = bytearray(data)

    @property
    def length(self):
        return len(self.data)

    @length.setter
    def length(self, length: int):
        if len(data) < length:
            data += b'\0' * (length - len(data))
        elif len(data) > length:
            data = data[:length]

    def __bytes__(self):
        return self.data

    def __len__(self):
        return len(self.data)

    def __getitem__(self, index: int|slice):
        if self._constructed or self._encapsulated:
            return super().__getitem__(index)
        length = len(self.data)
        if isinstance(index, int):
            if index >= length:
                return 0
            return self.data[index]
        if isinstance(index, slice):
            start, stop, step = self._make_range(index)
            chunk = self.data[start:length:step]
            if stop > length:
                chunk += b'\0' * (stop - length)
            return chunk
        raise TypeError('Asn1BitString indices must be integers or slices')

    def __setitem__(self, index: int|slice, value: int|bytes):
        length = len(self.data)
        if isinstance(index, int):
            if isinstance(value, bytes):
                if len(value) == 1:
                    value = value[0]
                else:
                    raise ValueError("number if bytes must be 1")
            if index >= length:
                self.data += b'\0' * (index - length + 1)
            self.data[index] = value
        elif isinstance(index, slice):
            if isinstance(value, int):
                value = itertools.repeat(value)
            start, stop, step = self._make_range(index)
            if index.stop is None and step > 0:
                irange = itertools.count(start, step)
            else:
                irange = range(start, stop, step)
            for ndx, v in zip(irange, value):
                self.__setitem__(ndx, v)
        else:
            raise TypeError('Asn1BitString indices must be integers or slices')

    def _make_range(self, index) -> tuple[int,int,int]:
        length = len(self.data)
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
        return start, stop, step

    def to_ber(self):
        if self._constructed or self._encapsulated:
            return super().to_ber()
        return self.data

    def from_ber(self, raw: bytes):
        if not super().from_ber(raw):
            self.data = bytearray(raw)
