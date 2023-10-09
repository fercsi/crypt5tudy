#!/usr/bin/python3

from .extension import Extension
from ..supported_extensions import _EXTENSION_HANDLERS
from ..util import *

def packExtensionList(extensions: list[Extension], size: int) -> bytes:
    exts = (ext.pack() for ext in extensions)
    return packBytesList(exts, size)

def unpackExtensionList(raw: bytes, pos: int, handshakeType: int, size: int) -> list[Extension]:
    endpos = pos + size + unpackInt(raw, pos, size)
    pos += size
    extensions = []
    while pos < endpos:
        extType = unpackU16(raw, pos)
        extContent = raw[pos:4+pos+unpackU16(raw, pos+2)]
        pos += len(extContent)
        extension = _EXTENSION_HANDLERS.get(extType)
        if extension is not None:
            extension = extension()
        else:
            extension = UnknownExtension(extType)
        extension.handshakeType = handshakeType
        extension.unpack(extContent)
        extensions.append(extension)
    return extensions
