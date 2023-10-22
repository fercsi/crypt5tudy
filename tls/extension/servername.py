#!/usr/bin/python3
# RFC8446

from typing import NamedTuple
from util.serialize import *
from .extension import Extension

class ServerInfo(NamedTuple):
    name: str
    type: int

class ServerName(Extension):
    def __init__(self, server_name: str|None = None):
        super().__init__()
        self.extension_type = 0
        self.names = []
        if server_name is not None:
            self.add(server_name)

    def add(self, name: str, type: int = 0) -> None:
        self.names.append(ServerInfo(name, type))

    def pack_extension_content(self):
        content = (pack_u8(n.type) + pack_str(n.name, 2) for n in self.names)
        return pack_bytes_list(content, 2)

    def unpack_extension_content(self, raw):
        srv_raw_list = unpack_bytes_list(raw, 0, 0, 2)
        for srv_raw in srv_raw_list:
            srv_type = unpack_u8(srv_raw, 0)
            srv_name = unpack_str(srv_raw, 1, 2)
            self.add(srv_name, srv_type)

    def represent(self, level: int = 0):
        text = super().represent(level);
        ind = '  '*level
        for v in self.names:
            type = 'host_name' if v.type == 0 else f'unknown type {v.type:0>2x}';
            text += ind + f'  - type: {type}\n'
            text += ind + f'    name: {v.name}\n'
        return text
