#!/usr/bin/python3
# RFC5077 - note that the recommended ticket format is not implemented (see 4.)

from tls.util import *
from .extension import Extension

class SessionTicket(Extension):
    def __init__(self, ticket: bytes = b''):
        super().__init__()
        self.extensionType = 35
        self.ticket = ticket

    def packExtensionContent(self) -> bytes:
        return self.ticket

    def unpackExtensionContent(self, raw: bytes) -> None:
        self.ticket = raw

    def represent(self, level: int = 0) -> str:
        text = super().represent(level, terminate=False)
        if self.ticket:
            text += self.ticket.hex() + '\n'
        else:
            text += '~\n'
        return text
