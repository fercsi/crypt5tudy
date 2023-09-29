#!/usr/bin/python3
# RFC4366

import sys
import os.path

#>sys.path.append('../../tls')
#>print(os.path.dirname(__file__))
sys.path.append(os.path.dirname(__file__) + '/..')

from tls.util import *

class Extension:
    def __init__(self):
        self.handshakeType = 0
        self.extensionType = 0xfafa

    def pack(self):
        type = self.extensionType.to_bytes(2, 'big')
        content = self.packExtensionContent()
        length = len(content).to_bytes(2, 'big')
        return type + length + content

    def unpack(self, raw):
        self.extensionType = unpackU16(raw, 0)
        self.unpackExtensionContent(raw[4:])

    def packExtensionContent(self):
        return b''

    def unpackExtensionContent(self, raw: bytes) -> None:
        pass

    def represent(self, level: int = 0, *, terminate: bool = True):
        ind = '  '*level
        text = ind + self.__class__.__name__ + ':' \
                                                + ('\n' if terminate else ' ')
        return text

    def __str__(self) -> str:
        return self.represent()


class UnknownExtension(Extension):
    def __init__(self, extType: int, content: bytes = b''):
        super().__init__()
        self.extensionType = extType
        self.content = content

    def packExtensionContent(self) -> bytes:
        return self.content

    def unpackExtensionContent(self, raw: bytes) -> None:
        self.content = raw

    def represent(self, level: int = 0):
        ind = '  '*level
        text = ind + f'Unknown extension (type {self.extensionType:0>4x}):\n'
        text += ind + '  Content: ' + self.content.hex() + '\n'
        return text
