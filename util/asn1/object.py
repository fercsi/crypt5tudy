#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

class Asn1Object:
    _constructed = False
    name: str|None = None

    def annotate(self, name: str):
        self.name = name

    def to_ber(self):
        return b''

    def from_ber(self, raw: bytes):
        pass

    def __str__(self):
        return self._represent(0)[:-1]

    def _represent(self, level: int):
#>        name = self.name or f'[{self._type_name}]'
#>        return '  ' * level + name + ': ' + self._repr_content(level) + '\n'
        name = (self.name or '') + f'[{self._type_name}]'
        constructed = ('*' if self._constructed else '')
        classstr = (f'{self._class}#' if self._class else '')
        return '  ' * level + constructed + classstr + name + ': ' + self._repr_content(level) + '\n'

    def _repr_content(self, level: int):
        return '~'
