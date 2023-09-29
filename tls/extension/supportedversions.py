#!/usr/bin/python3
# RFC8446

from tls.util import *
from .extension import Extension

VERSION_IDS: dict[str, int] = {
    'tls1.2': 0x0303,
    'tls1.3': 0x0304,
    'v1.2': 0x0303,
    'v1.3': 0x0304,
    '1.2': 0x0303,
    '1.3': 0x0304,
    }

class SupportedVersions(Extension):
    def __init__(self, versions: list[str|int]|None = None):
        super().__init__()
        self.extensionType = 43
        self.versions = []
        if versions:
            self.add(versions)

    def add(self, version: str|int|list) -> None:
        if not isinstance(version, list):
            version = [version]
        version = (VERSION_IDS[g.replace('-', '_').lower()]
                if isinstance(g, str) else g for g in version)
        self.versions.extend(version)

    def packExtensionContent(self) -> bytes:
        if self.handshakeType == 1:
            return packU16List(self.versions, 1)
        elif self.handshakeType == 2:
            return packU16(self.versions[0])
        else:
            raise TypeError(f"Don't know, how to pack `SupportedVersion` for handshake type {self.handshakeType}")

    def unpackExtensionContent(self, raw):
        if self.handshakeType == 1:
            self.versions = unpackU16List(raw, 0, 1)
        elif self.handshakeType == 2:
            self.versions = [unpackU16(raw, 0)]
        else:
            raise TypeError(f"Don't know, how to unpack `SupportedVersion` for handshake type {self.handshakeType}")

    def represent(self, level: int = 0):
        text = super().represent(level);
        ind = '  '*level
        revlut = {}
        for k, v in VERSION_IDS.items():
            if k[0] == 't':
                revlut[v] = k
        for v in self.versions:
            t = revlut.get(v)
            if t is not None:
                text += ind + f'  - {t}\n'
            else:
                text += ind + f'  - unknown version {t:0>4x}\n'
        return text
