#!/usr/bin/python3
# RFC8446

from typing import NamedTuple
from tls.util import *
from .extension import Extension

class ServerInfo(NamedTuple):
    name: str
    type: int

class ServerName(Extension):
    def __init__(self, serverName: str|None = None):
        super().__init__()
        self.extensionType = 0
        self.names = []
        if serverName is not None:
            self.add(serverName)

    def add(self, name: str, type: int = 0) -> None:
        self.names.append(ServerInfo(name, type))

    def packExtensionContent(self):
        content = (packU8(n.type) + packStr(n.name, 2) for n in self.names)
        return packBytesList(content, 2)
