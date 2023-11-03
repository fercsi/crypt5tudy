#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object

class Asn1BitString(Asn1Object):
    _type_id = 3
    _type_name = 'BIT STRING'

    _default_format: str = 'hex_block'
    _length: int = 0
    data: bytearray
    content: list[Asn1Object]|None = None

    def __init__(self, bits: list[int] = []):
        super().__init__()
        self.data = bytearray()
        for i in bits:
            self.__setitem__(i, 1)

    @property
    def length(self) -> int:
        return self._length

    @length.setter
    def length(self, length) -> None:
        if length < self._length:
            bitlen = length + 7 >> 3
            self.data = self.data[:bitlen]
            self.data[-1] &= ~((1 << (-length & 7)) - 1)
        elif length > self._length:
            add = (length + 7 >> 3) - len(self.data)
            self.data += b'\0' * add
        self._length = length

    def __bytes__(self):
        return self.data

    def __getitem__(self, index: int|range):
        if isinstance(index, int):
            if index < -self._length:
                raise IndexError('index out of range')
            if index >= self._length:
                return 0
            if index < 0:
                index = self._length - index
            return 1 if self.data[index >> 3] & (1 << (~index & 7)) else 0
        if isinstance(index, slice):
            irange = self._make_range(indwx)
            value = 0
            for i in irange:
                value <<= 1
                value |= self.__getitem__(i)
            return value
        raise TypeError('Asn1BitString indices must be integers or slices')

    def __setitem__(self, index: int|range, value: int):
        if isinstance(index, int):
            if index < -self._length:
                raise IndexError('index out of range')
            if index >= self._length:
                # Note: intentionally use property setter!:
                self.length = index + 1
            if index < 0:
                index = self._length - index
            mask = 1 << (~index & 7)
            if value:
                self.data[index >> 3] |= mask
            else:
                self.data[index >> 3] &= ~mask
        elif isinstance(index, slice):
            indices = reversed(self._make_range(index))
            for idx in indices:
                self.__setitem__(idx, value & 1)
                value >>= 1
        else:
            raise TypeError('Asn1BitString indices must be integers or slices')

    def _make_range(self, index):
        start = index.start
        stop = index.stop
        step = index.step or 1
        if start is None:
            if step < 0:
                start = self._length - 1
            else:
                start = 0
        elif start < 0:
            start += self._length
        if stop is None:
            if step < 0:
                stop = -1
            else:
                stop = self._length
        elif stop < 0:
            stop += self._length
        return range(start, stop, step)

    def process_encapsulated(self):
        super().process_encapsulated(self.data)

    def to_ber(self):
        if self._constructed or self._encapsulated:
            return super().to_ber()
        return pack_u8(-self._length & 7) + self.data

    def from_ber(self, raw: bytes):
        if not super().from_ber(raw):
            self.data = bytearray(raw[1:])
            self._length = len(raw) * 8 - 8 - raw[0]

    def _repr_content(self, level: int):
        if self._constructed or self._encapsulated:
            return super()._repr_content(level)
        text = self.format_data(self.data, level + 1)
        if self.format in ('bin', 'bin_block'):
            not_used = -self._length & 7
            if not_used:
                text = text[:-not_used] + '-' * not_used
        return text
        # in case of hex_block, "not used" info is not displayed
