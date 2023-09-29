#!/usr/bin/python3
# RFC7366 - no effect in TLS1.3 (it is used anyways)

from .extension import Extension

class EncryptThenMAC(Extension):
    def __init__(self):
        super().__init__()
        self.extensionType = 22

    def packExtensionContent(self) -> bytes:
        return b''

    def unpackExtensionContent(self, raw: bytes) -> None:
        pass

    def represent(self, level: int = 0) -> str:
        text = super().represent(level, terminate=False)
        text += '~\n'
        return text
