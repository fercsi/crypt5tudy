#!/usr/bin/python3
# RFC7366 - no effect in TLS1.3 (it is used anyways)

from .extension import Extension

class EncryptThenMAC(Extension):
    def __init__(self):
        super().__init__()
        self.extension_type = 22

    def pack_extension_content(self) -> bytes:
        return b''

    def unpack_extension_content(self, raw: bytes) -> None:
        pass

    def represent(self, level: int = 0) -> str:
        text = super().represent(level, terminate=False)
        text += '~\n'
        return text
