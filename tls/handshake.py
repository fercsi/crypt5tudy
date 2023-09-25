#!/usr/bin/python3
# RFC8446

from .util import *
from .record import Record
from .extension import Extension
from .supported_extensions import *
from .supported_extensions import _EXTENSION_HANDLERS

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

    def addExtension(self, ext: Extension) -> None:
        self.extensions.append(ext)

    def packExtensions(self) -> bytes:
        exts = (ext.pack() for ext in self.extensions)
        return packBytesList(exts, 2)

    def unpackExtensions(self, raw: bytes) -> None:
        pos = 0
        length = len(raw)
        while pos < length:
            type = unpackU16(raw, pos)
            extContent = unpackBytes(raw, pos+2, 2)
            pos += len(extContent) + 4
            extension = _EXTENSION_HANDLERS.get(extType)
            if extension is None:
                extension = Unknown(extType)
            extension.unpack(raw)
            self.addExtension(extension)


class UnknownHandshake(Handshake):
    def __init__(self, handshakeType: int, content: bytes):
        super().__init__()
        self.handshakeType = handshakeType
        self.content = content

    def packHandshakeContent(self) -> bytes:
        return self.content

    def packHandshakeContent(self, raw: bytes) -> None:
        self.content = raw
