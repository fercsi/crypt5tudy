#!/usr/bin/python3
# RFC7627 - no effect in TLS1.3

from tls.util import *
from .extension import Extension

class ExtendedMasterSecret(Extension):
    def __init__(self, secret: bytes = b''):
        super().__init__()
        self.extension_type = 23
        self.secret = secret

    def pack_extension_content(self) -> bytes:
        return self.secret

    def unpack_extension_content(self, raw: bytes) -> None:
        self.secret = raw

    def represent(self, level: int = 0) -> str:
        text = super().represent(level, terminate=False)
        if self.secret:
            text += self.secret.hex() + '\n'
        else:
            text += '~\n'
        return text
