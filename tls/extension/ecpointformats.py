#!/usr/bin/python3
# RFC4492

from tls.util import *
from .extension import Extension

FORMAT_IDS: dict[str, int] = {
    'uncompressed': 0,
    'ansiX962_compressed_prime': 1,
    'ansiX962_compressed_char2': 2,
    }

class EcPointFormats(Extension):
    def __init__(self, formats: list[str|int]|None = None):
        super().__init__()
        self.extensionType = 11
        if formats:
            self.formats = []
            self.add(formats)
        else:
            self.formats = [0]

    def add(self, format: str|int|list) -> None:
        if not isinstance(format, list):
            format = [format]
        format = (FORMAT_IDS[f] if isinstance(f, str) else f for f in format)
        self.formats.extend(format)

    def packExtensionContent(self):
        return packU8List(self.formats, 1)

    def unpackExtensionContent(self, raw):
        self.formats = unpackU8List(raw, 0, 1)

    def represent(self, level: int = 0):
        text = super().represent(level);
        ind = '  '*level
        revlut = {}
        for k, v in FORMAT_IDS.items():
            revlut[v] = k
        for v in self.formats:
            t = revlut.get(v)
            if t is not None:
                text += ind + f'  - {t}\n'
            else:
                text += ind + f'  - unknown_{t:0>4x}\n'
        return text
