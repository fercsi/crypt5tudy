#!/usr/bin/python3
# RFC4366

import sys
import os.path

#>sys.path.append('../../tls')
#>print(os.path.dirname(__file__))
sys.path.append(os.path.dirname(__file__) + '/..')

from uti.pack import *

class Extension:
    def __init__(self):
        self.extensionType = 0xfafa

    def pack(self):
        type = self.extensionType.to_bytes(2, 'big')
        content = self.packExtensionContent()
        length = len(content).to_bytes(2, 'big')
        return type + length + content

    def packExtensionContent(self):
        return b''


class UnknownExtension(Extension):
    def __init__(self, extType: int, content: bytes = b''):
        super().__init__()
        self.extensionType = extType
        self.content = content

    def packExtensionContent(self) -> bytes:
        return self.content

    def inpackExtensionContent(self, raw: bytes) -> None:
        self.content = raw
