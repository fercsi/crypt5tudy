#!/usr/bin/python3
# RFC8446

from util.serialize import *
from util.verbose import *
from tls.message import Message
from tls.extension import Extension, pack_extension_list, unpack_extension_list
#>from tls.supported_extensions import *
#>from tls.supported_extensions import _EXTENSION_HANDLERS

class Handshake(Message):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.message_type = 22
        self.handshake_type = 0
        self.extensions = []

    def pack_message_content(self) -> bytes:
        type = pack_u8(self.handshake_type)
        content = pack_bytes(self.pack_handshake_content(), 3)
        return type +  content

    def pack_handshake_content(self) -> bytes:
        return b''

    def unpack_message_content(self, raw: bytes) -> None:
        self.handshake_type = unpack_u8(raw, 0)
        raw_content = unpack_bytes(raw, 1, 3)
        self.unpack_handshake_content(raw_content)

    def unpack_handshake_content(self, raw: bytes) -> None:
        pass

    def add_extension(self, extension: Extension) -> None:
        extension.handshake_type = self.handshake_type
        self.extensions.append(extension)
        verbose(3, self.verbosity, f"Extension {type(extension).__name__} added")

    def pack_extensions(self) -> bytes:
        return pack_extension_list(self.extensions, 2)
#>        exts = (ext.pack() for ext in self.extensions)
#>        return pack_bytes_list(exts, 2)

    def unpack_extensions(self, raw: bytes, pos: int) -> None:
        extensions = unpack_extension_list(raw, pos, self.handshake_type, 2,
                                                                   message=self)
        for extension in extensions:
            self.add_extension(extension)
#>
#>    def _unpackExtensions(self, raw: bytes) -> list[Extension]:
#>        pos = 0
#>        length = len(raw)
#>        extensions = []66
#>        while pos < length:
#>            ext_type = unpack_u16(raw, pos)
#>            ext_content = raw[pos:4+pos+unpack_u16(raw, pos+2)]
#>            pos += len(ext_content)
#>            extension = _EXTENSION_HANDLERS.get(ext_type)
#>            if extension is not None:
#>                extension = extension()
#>            else:
#>                extension = UnknownExtension(ext_type)
#>            extension.handshake_type = self.handshake_type
#>            extension.unpack(ext_content)
#>            extensions.append(extension)
#>        return extensions


class UnknownHandshake(Handshake):
    def __init__(self, handshake_type: int, content: bytes = b''):
        super().__init__()
        self.handshake_type = handshake_type
        self.content = content

    def pack_handshake_content(self) -> bytes:
        return self.content

    def pack_handshake_content(self, raw: bytes) -> None:
        self.content = raw

    def represent(self) -> str:
        return f'Handshake-unknown_{self.handshake_type:0>2x}:\n' \
             + f'  Content: {self.content.hex()}\n'
