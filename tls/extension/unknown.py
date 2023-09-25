#!/usr/bin/python3

from .extension import Extension

class Unknown(Extension):
    def __init__(self, extType: int, content: bytes = b''):
        super().__init__()
        self.extensionType = extType
        self.content = content

    def packExtensionContent(self) -> bytes:
        return self.content

    def inpackExtensionContent(self, raw: bytes) -> None:
        self.content = raw
