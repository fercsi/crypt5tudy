#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *
from .object import Asn1Object

class Asn1BitString(Asn1Object):
    # TODO: constructed
    _type_id = 3
    _type_name = 'BIT STRING'

    bits: bytearray
    length: int = 0
    display_mode: str = 'hex_block'
    content: list[Asn1Object]|None = None

    def __init__(self):
        super().__init__()
        self.bits = bytearray()

    def __bytes__(self):
        return self.bits

    def __getitem__(self, index: int|range):
        if isinstance(index, int):
            if index < -self.length:
                raise IndexError('index out of range')
            if index >= self.length:
                return 0
            if index < 0:
                index = self.length - index
            return 1 if self.bits[index >> 3] & (1 << (~index & 7)) else 0
        if isinstance(index, slice):
            start = index.start
            stop = index.stop
            step = index.step or 1
            if start is None:
                if step < 0:
                    start = self.length - 1
                else:
                    start = 0
            elif start < 0:
                start += self.length
            if stop is None:
                if step < 0:
                    stop = -1
                else:
                    stop = self.length
            elif stop < 0:
                stop += self.length
            value = 0
            for i in range(start, stop, step):
                value <<= 1
                value |= self.__getitem__(i)
            return value
        raise TypeError('Asn1BitString indices must be integers or slices')

    def __setitem__(self, index: int|range, value: int):
        if isinstance(index, int):
            if index < -self.length:
                raise IndexError('index out of range')
            if index >= self.length:
                self.set_length(index + 1)
            if index < 0:
                index = self.length - index
            mask = 1 << (~index & 7)
            if value:
                self.bits[index >> 3] |= mask
            else:
                self.bits[index >> 3] &= ~mask
            return
        if isinstance(index, slice):
            NotImplemented # TODO 
        raise TypeError('Asn1BitString indices must be integers or slices')

    def set_length(self, length) -> None:
        if length < self.length:
            bitlen = length + 7 >> 3
            self.bits = self.bits[:bitlen]
            self.bits[-1] &= ~((1 << (-length & 7)) - 1)
        elif length > self.length:
            add = (length + 7 >> 3) - len(self.bits)
            self.bits += b'\0' * add
        self.length = length

    def annotate(self, name: str|None, attributes = None):
        """Annotates either bits or an encapsulated object

        attributes types:
        - content (if content is encapsulated)
        - display_mode (if not)
        """
        if not super().annotate(name, attributes):
            self.display_mode = attributes or 'hex'

    def process_encapsulated(self):
        super().process_encapsulated(self.bits)

    def to_ber(self):
        if self._constructed or self._encapsulated:
            return super().to_ber()
        return pack_u8(-self.length & 7) + self.bits

    def from_ber(self, raw: bytes):
        self.bits = bytearray(raw[1:])
        self.length = len(raw) * 8 - 8 - raw[0]

    def _repr_content(self, level: int):
        if self._constructed or self._encapsulated:
            return super()._repr_content(level)
        text = self.format_data(self.display_mode, self.bits, level + 1)
        if self.display_mode in ('bin', 'bin_block'):
            not_used = -self.length & 7
            if not_used:
                text = text[:-not_used] + '-' * not_used
        return text
        # in case of hex_block, "not used" info is not displayed