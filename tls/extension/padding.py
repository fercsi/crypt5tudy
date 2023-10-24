#!/usr/bin/python3
# RFC7685

from util.serialize import *
from .extension import Extension

class Padding(Extension):
    def __init__(self, length: int = 0):
        super().__init__()
        self.extension_type = 21
        self.padding = b'\0' * length

    def set_length(self, length: int) -> None:
        self.padding = b'\0' * length

    def pack_extension_content(self) -> bytes:
        return pack_bytes(self.padding, 2)

    def unpack_extension_content(self, raw: bytes) -> None:
        # Note we store the whole content (theoretically it must be sound
        # NULL-s). We don't check it, but it can be checked from outside
        self.padding = unpack_bytes(raw, 0, 2)

    def represent(self, level: int = 0) -> str:
        text = super().represent(level)
        text += '  ' * level + f'  Length: {len(self.padding)}'
        return text
