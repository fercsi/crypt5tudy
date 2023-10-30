#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

class Asn1Object:
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
