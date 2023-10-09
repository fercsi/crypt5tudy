#!/usr/bin/python3
# RFC8446

from tls.util import *
from tls.record import Record
from tls.extension import Extension, packExtensionList, unpackExtensionList
#>from tls.supported_extensions import *
#>from tls.supported_extensions import _EXTENSION_HANDLERS

class Handshake(Record):
    def __init__(self):
        super().__init__()
        self.recordType = 22
        self.handshakeType = 0
        self.extensions = []

    def packRecordContent(self) -> bytes:
        type = packU8(self.handshakeType)
        content = packBytes(self.packHandshakeContent(), 3)
        return type +  content

    def packHandshakeContent(self) -> bytes:
        return b''

    def unpackRecordContent(self, raw: bytes) -> None:
        self.handshakeType = unpackU8(raw, 0)
        rawContent = unpackBytes(raw, 1, 3)
        self.unpackHandshakeContent(rawContent)

    def unpackHandshakeContent(self, raw: bytes) -> None:
        pass

    def addExtension(self, extension: Extension) -> None:
        extension.handshakeType = self.handshakeType
        self.extensions.append(extension)

    def packExtensions(self) -> bytes:
        return packExtensionList(self.extensions, 2)
#>        exts = (ext.pack() for ext in self.extensions)
#>        return packBytesList(exts, 2)

    def unpackExtensions(self, raw: bytes, pos: int) -> None:
        extensions = unpackExtensionList(raw, pos, self.handshakeType, 2)
        for extension in extensions:
            self.addExtension(extension)
#>
#>    def _unpackExtensions(self, raw: bytes) -> list[Extension]:
#>        pos = 0
#>        length = len(raw)
#>        extensions = []66
#>        while pos < length:
#>            extType = unpackU16(raw, pos)
#>            extContent = raw[pos:4+pos+unpackU16(raw, pos+2)]
#>            pos += len(extContent)
#>            extension = _EXTENSION_HANDLERS.get(extType)
#>            if extension is not None:
#>                extension = extension()
#>            else:
#>                extension = UnknownExtension(extType)
#>            extension.handshakeType = self.handshakeType
#>            extension.unpack(extContent)
#>            extensions.append(extension)
#>        return extensions


class UnknownHandshake(Handshake):
    def __init__(self, handshakeType: int, content: bytes = b''):
        super().__init__()
        self.handshakeType = handshakeType
        self.content = content

    def packHandshakeContent(self) -> bytes:
        return self.content

    def packHandshakeContent(self, raw: bytes) -> None:
        self.content = raw

    def represent(self) -> str:
        return f'Handshake-unknown_{self.handshakeType:0>2x}:\n' \
             + f'  Content: {self.content.hex()}\n'
