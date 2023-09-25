#!/usr/bin/python3
# RFC4492

from .util import *
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
