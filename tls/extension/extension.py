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
        self.handshake_type = 0
        self.extension_type = 0xfafa

    def pack(self):
        type = self.extension_type.to_bytes(2, 'big')
        content = self.pack_extension_content()
        length = len(content).to_bytes(2, 'big')
        return type + length + content

    def unpack(self, raw):
        self.extension_type = unpack_u16(raw, 0)
        self.unpack_extension_content(raw[4:])

    def pack_extension_content(self):
        return b''

    def unpack_extension_content(self, raw: bytes) -> None:
        pass

    def represent(self, level: int = 0, *, terminate: bool = True):
        ind = '  '*level
        text = ind + self.__class__.__name__ + ':' \
                                                + ('\n' if terminate else ' ')
        return text

    def __str__(self) -> str:
        return self.represent()


class UnknownExtension(Extension):
    def __init__(self, ext_type: int, content: bytes = b''):
        super().__init__()
        self.extension_type = ext_type
        self.content = content

    def pack_extension_content(self) -> bytes:
        return self.content

    def unpack_extension_content(self, raw: bytes) -> None:
        self.content = raw

    def represent(self, level: int = 0):
        ind = '  '*level
        text = ind + f'Unknown extension (type {self.extension_type:0>4x}):\n'
        text += ind + '  Content: ' + self.content.hex() + '\n'
        return text
