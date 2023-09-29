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

    def unpackExtensionContent(self, raw):
        srvRawList = unpackBytesList(raw, 0, 0, 2)
        for srvRaw in srvRawList:
            srvType = unpackU8(srvRaw, 0)
            srvName = unpackStr(srvRaw, 1, 2)
            self.add(srvName, srvType)

    def represent(self, level: int = 0):
        text = super().represent(level);
        ind = '  '*level
        for v in self.names:
            type = 'host_name' if v.type == 0 else f'unknown type {v.type:0>2x}';
            text += ind + f'  - type: {type}\n'
            text += ind + f'    name: {v.name}\n'
        return text
