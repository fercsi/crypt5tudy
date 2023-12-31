#!/usr/bin/python3

from .extension import Extension, UnknownExtension
from ..supported_extensions import _EXTENSION_HANDLERS
from util.serialize import *

def pack_extension_list(extensions: list[Extension], size: int, **kwargs) -> bytes:
    exts = (ext.pack(**kwargs) for ext in extensions)
    return pack_bytes_list(exts, size)

def unpack_extension_list(raw: bytes, pos: int, handshake_type: int, lensize: int, **kwargs) -> list[Extension]:
    endpos = pos + lensize + unpack_uint(raw, pos, lensize)
    pos += lensize
    extensions = []
    while pos < endpos:
        ext_type = unpack_u16(raw, pos)
        ext_content = raw[pos:4+pos+unpack_u16(raw, pos+2)]
        pos += len(ext_content)
        extension = _EXTENSION_HANDLERS.get(ext_type)
        if extension is not None:
            extension = extension()
        else:
            extension = UnknownExtension(ext_type)
        extension.handshake_type = handshake_type
        extension.unpack(ext_content, **kwargs)
        extensions.append(extension)
    return extensions
