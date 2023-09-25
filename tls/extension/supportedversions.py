#!/usr/bin/python3
# RFC8446

from .util import *
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

    def packExtensionContent(self):
        return packU16List(self.versions, 1)
