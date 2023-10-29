#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from util.serialize import *

class Ans1Object:
    _constructed = False
    name: str|None = None

    def annotate(self, name: str):
        self.name = name

    def __str__(self):
        return self._represent(0)[:-1]

    def _represent(self, level: int):
        name = self.name or f'[{self._type_name}]'
        return '  ' * level + name + ': ' + self._repr_content(level) + '\n'

    def _repr_content(self, level: int):
        return '~'

class Ans1Boolean(Ans1Object):
    _type_id = 1
    _type_name = 'BOOLEAN'

    value: bool = False

    def __init__(self, value: bool = False):
        self.value = True if value else False

    def __bool__(self):
        return self.value

    def to_ber(self):
        return b'\xff' if self.value else b'\0'

    def from_ber(self, raw: bytes):
        self.value = raw[0] > 0

    def _repr_content(self, level: int):
        return 'true' if self.value else 'false'

class Ans1Integer(Ans1Object):
    _type_id = 2
    _type_name = 'INTEGER'

    value: int = 0
    length: int|None = None
    display_mode: str = 'dec' # 'hex',

    def __init__(self, value: int = 0, length: int|None = None):
        self.value = int(value)
        self.length = length

    def __int__(self):
        return self.value

    def annotate(self, name: str|None, display_mode: str|None = None):
        self.name = name
        self.display_mode = display_mode or 'dec'

    def to_ber(self):
        return pack_int(self.value, self.length)

    def from_ber(self, raw: bytes):
        self.value = unpack_int(raw, 0, len(raw))
        self.length = len(raw)

    def _repr_content(self, level: int):
        if self.display_mode == 'hex':
            if self.length:
                return ('{:0>' + str(self.length * 2) + 'x}').format(self.value)
            h = hex(self.value)
            if len(h) & 1:
                h = '0' + h
            return h
        elif self.display_mode == 'block':
            text = '\n'
            byte_form = self.to_ber()
            for i in range(0, len(byte_form), 16):
                text += '  ' * level + '  ' + ' '.join(f'{b:0>2x}' for b in byte_form[i:i+16]) + '\n'
            return text[:-1]
        else:
            return str(self.value)

class Ans1BitString(Ans1Object):
    _type_id = 3
    _type_name = 'BIT STRING'

    bits: bytearray
    length: int = 0
    display_mode: str = 'hex' # 'bin', 'block'
    encapsulated: list[Ans1Object]|None = None

    def __init__(self):
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
        raise TypeError('Ans1BitString indices must be integers or slices')

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
        raise TypeError('Ans1BitString indices must be integers or slices')

    def set_length(self, length) -> None:
        if length < self.length:
            bitlen = length + 7 >> 3
            self.bits = self.bits[:bitlen]
            self.bits[-1] &= ~((1 << (-length & 7)) - 1)
        elif length > self.length:
            add = (length + 7 >> 3) - len(self.bits)
            self.bits += b'\0' * add
        self.length = length

    def annotate(self, name: str|None, display_mode: str|None = None):
        self.name = name
        self.display_mode = display_mode or 'hex'

    def encapsulate(self, ans1_object: Ans1Object):
        self._type_name = 'BIT STRING (encapsulated)'
        if self.encapsulated is None:
            self.encapsulated = []
        self.encapsulated.apoend(ans1_object)

    def process_encapsulated(self):
        self._type_name = 'BIT STRING (encapsulated)'
        self.encapsulated = []
        pos = 0
        endpos = len(self.bits)
        while pos < endpos:
            obj, pos = Ans1._from_ber(self.bits, pos)
            self.encapsulated.append(obj)

    def to_ber(self):
        if self.encapsulated is not None:
            return b'\0' + b''.join(o.to_ber() for o in self.encapsulated)
        return pack_u8() + self.bits

    def from_ber(self, raw: bytes):
        self.bits = bytearray(raw[1:])
        self.length = len(raw) * 8 - 8 - raw[0]

    def _repr_content(self, level: int):
        if self.encapsulated is not None:
            return '\n' + ''.join(o._represent(level + 1) for o in self.encapsulated)[:-1]
        if self.display_mode == 'bin':
            text = '\n'
            bits = self.bits
            for i in range(0, len(bits), 4):
                text += '  ' * level + '  ' + ' '.join(f'{b:0>8b}' for b in bits[i:i+4]) + '\n'
            text = text[:-1]
            not_used = -self.length & 7
            if not_used:
                text = text[:-not_used] + '-' * not_used
            return text
        elif self.display_mode == 'block':
            text = '\n'
            byte_form = self.to_ber()
            for i in range(0, len(byte_form), 16):
                text += '  ' * level + '  ' + ' '.join(f'{b:0>2x}' for b in byte_form[i:i+16]) + '\n'
            return text[:-1]
        else: # hex
            return self.bits.hex()

class Ans1Null(Ans1Object):
    _type_id = 5
    _type_name = 'NULL'

    def __init__(self, bits: bytes = b''):
        self.bits = bits

    def to_ber(self):
        return b''

    def from_ber(self, raw: bytes):
        pass

    def _repr_content(self, level: int):
        return '~'

class Ans1ObjectIdentifier(Ans1Object):
    _type_id = 6
    _type_name = 'OBJECT IDENTIFIER'

    arcs: list[int]

    def __init__(self, arcs: list[int] = []):
        self.arcs = arcs

    def to_ber(self):
        if not self.arcs:
            return b''
        b0 = self.arcs[0] * 40
        if len(self.arcs) == 1:
            return b0
        b0 += self.arcs[1]
        text = pack_u8(b0)
        for arc in self.arcs[2:]:
#>            print('!',arc)
            parts = []
            if arc:
                parts = []
                while arc:
                    parts.append(arc & 0x7f)
                    arc >>= 7
            else:
                parts = [0]
            parts = parts[:1] + [0x80|b for b in parts[1:]]
            text += bytes(reversed(parts))
        return text

    def from_ber(self, raw: bytes):
        if not raw:
            self.arcs = []
            return
        self.arcs = list(divmod(raw[0], 40))
        pos = 1
        endpos = len(raw)
        while pos < endpos:
            arc = 0
            part = raw[pos]
            pos += 1
            while part & 0x80:
                arc |= part & 0x7f
                arc <<= 7
                part = raw[pos]
                pos += 1
            arc |= part
            self.arcs.append(arc)

    def _repr_content(self, level: int):
        return '.'.join(str(a) for a in self.arcs)

class Ans1Sequence(Ans1Object):
    _type_id = 16
    _type_name = 'SEQUENCE'
    _constructed = True

    content: list[Ans1Object]

    def __init__(self):
        self.content = []

    def append(self, ans1_object: Ans1Object):
        self.content.append(ans1_object)

    def annotate(self, name: str|None, content: list[tuple]|None = None):
        self.name = name
        if content is not None:
            for item, ann in zip(self.content, content):
                item.annotate(*ann)

    def to_ber(self):
        content = b''
        for ans1_object in self.content:
            content += Ans1.to_ber(ans1_object)
        return content

    def from_ber(self, raw: bytes):
        pos = 0
        self.content = []
        while pos < len(raw):
            ans1_object, pos = Ans1._from_ber(raw, pos)
            self.append(ans1_object)

    def _repr_content(self, level: int):
        text = '\n'
        for ans1_object in self.content:
            text += ans1_object._represent(level + 1)
        return text[:-1]

class Ans1NotImplemented(Ans1Object):
    _type_name = 'NOT IMPLEMENTED'
    content: bytes

    def to_ber(self):
        return self.content

    def from_ber(self, raw: bytes):
        self.content = raw

    def _repr_content(self, level: int):
        return f'{self._type_id}, ' + self.content.hex()

_TYPE_HANDLERS = {
     1: Ans1Boolean,
     2: Ans1Integer,
     3: Ans1BitString,
     5: Ans1Null,
     6: Ans1ObjectIdentifier,
    16: Ans1Sequence,
}

class Ans1:

    @staticmethod
    def to_ber(ans1_object: Ans1Object) -> bytes:
        content = ans1_object.to_ber()
        ans1_type = ans1_object._type_id | (0x20 if ans1_object._constructed else 0)
        length = len(content)
        if length < 0x80:
            raw_len = pack_u8(length)
        else:
            raw_len = pack_int(length)
            raw_len = pack_u8(0x80 + len(raw_len)) + raw_len
        return pack_u8(ans1_type) + raw_len + content

    @staticmethod
    def from_ber(raw: bytes):
        return Ans1._from_ber(raw, 0)[0]

    @staticmethod
    def _from_ber(raw: bytes, pos: int = 0):
        ans1_type = raw[pos]
        pos += 1
        constructed = (ans1_type & 0x20) != 0
        type_class = ans1_type >> 6
        ans1_type &= 0x1f
        if ans1_type == 0x1f:
            ans1_type = raw[pos]
            pos += 1
        length = raw[pos]
        pos += 1
        if length & 0x80:
            ll = length & 0x7f
            length = unpack_int(raw, pos, ll)
            pos += ll
        data = raw[pos:pos+length]
        pos += length
        content = Ans1._process_type(ans1_type, constructed, type_class, data)
        return content, pos

    @staticmethod
    def _process_type(ans1_type: int, constructed: bool, type_class: int, data: bytes):
        if type_class > 0:
            type_handler = Ans1NotImplemented
        else:
            type_handler = _TYPE_HANDLERS.get(ans1_type, Ans1NotImplemented)
        content = type_handler()
        content._type_id = ans1_type
        content._constructed = constructed
        content.from_ber(data)
        return content
