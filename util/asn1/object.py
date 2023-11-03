#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from typing import Self

class Asn1Object:
    _constructed: bool = False
    _encapsulated: bool = False
    _class: int # 0..3
    _raw: bytes
    name: str|None = None
    content: list[Self]
    _default_format: str = 'hex_block'
    format: str
    data: bytes|None

    def __init__(self):
        self.content = []
        self.format = self._default_format
        self.data = None

    def annotate(self, name: str|None, items: list[tuple]|None = None):
        self.name = name
        if (self._constructed or self._encapsulated) and items is not None:
            for item, annotation in zip(self.content, items):
                if annotation:
                    item.annotate(*annotation)
        else:
            self.format = items or self._default_format

    def append(self, asn1_object: Self):
        self.content.append(asn1_object)

    def encapsulate(self, asn1_object: Self):
        self._encapsulated = True
        self.content.append(asn1_object)

    def process_encapsulated(self, raw: bytes|None = None):
        from .asn1 import Asn1
        self._encapsulated = True
        self.content = []
        raw = raw or self._raw
        pos = 0
        endpos = len(raw)
        while pos < endpos:
            obj, pos = Asn1._from_ber(raw, pos)
            self.content.append(obj)

    def to_ber(self):
        # Bitstring: if encapsulated b'\0'+super()...
        if self._constructed or self._encapsulated:
            from .asn1 import Asn1
            content = b''
            for asn1_object in self.content:
                content += Asn1.to_ber(asn1_object)
            return content
        return b''

    def from_ber(self, raw: bytes) -> bool:
        if self._constructed:
            from .asn1 import Asn1
            pos = 0
            self.content = []
            while pos < len(raw):
                asn1_object, pos = Asn1._from_ber(raw, pos)
                self.append(asn1_object)
            return True
        return False

    def __str__(self):
        return self._represent(0)[:-1]

    def _represent(self, level: int):
        constructed = ('*' if self._constructed else '')
        encapsulated = ('#' if self._encapsulated else '')
        contained = constructed + encapsulated
        class_str = ['','APP:','CTX:','PRI:'][self._class] # Universal, Application, Context specific, Private
        name = (self.name or '') + f'[{class_str}{self._type_name}]'
        content = self._repr_content(level) or '~'
        sep = ':' if content[0] == '\n' else ': '
#>        print('|', name)
#>        print('|', self._repr_content(level))
        return '  ' * level + contained + name + sep + content + '\n'

    def _repr_content(self, level: int):
        if self._constructed or self._encapsulated:
            text = '\n'
            for asn1_object in self.content:
                text += asn1_object._represent(level + 1)
            return text[:-1]
        if self.data:
            return self.format_data(self.data, level + 1)
        return '~'

    def format_data(self, data: bytes, level: int) -> str:
        if self.format == 'dec':
            return str(int.from_bytes(data, 'big'))
        if self.format == 'hex':
            return data.hex()
        if self.format == 'bin':
            return ''.join(f'{b:0>8b}' for b in data)
        if self.format == 'hex_block':
            text = '\n'
            for i in range(0, len(data), 16):
                text += '  ' * level \
                            + ' '.join(f'{b:0>2x}' for b in data[i:i+16]) + '\n'
            return text[:-1]
        if self.format == 'bin_block':
            text = '\n'
            for i in range(0, len(data), 4):
                text += '  ' * level \
                            + ' '.join(f'{b:0>8b}' for b in data[i:i+4]) + '\n'
            return text[:-1]
        if self.format == 'str':
            return repr(data.decode('utf8', errors='replace'))
        if self.format[:4] == 'str_':
            encoding = self.format[4:]
            return repr(data.decode(encoding, errors='replace'))
        raise ValueError(f"unknown data format '{format}'")
