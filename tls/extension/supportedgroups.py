#!/usr/bin/python3
# RFC8446

from .util import *
from .extension import Extension

GROUP_IDS: dict[str, int] = {
    'secp256r1': 0x0017,
    'secp384r1': 0x0018,
    'secp521r1': 0x0019,
    'x25519': 0x001D,
    'x448': 0x001E,
    'ffdhe2048': 0x0100,
    'ffdhe3072': 0x0101,
    'ffdhe4096': 0x0102,
    'ffdhe6144': 0x0103,
    'ffdhe8192': 0x0104,
    }

class SupportedGroups(Extension):
    def __init__(self, groups: list[str|int]|None = None):
        super().__init__()
        self.extensionType = 10
        self.groups = []
        if groups:
            self.add(groups)

    def add(self, group: str|int|list) -> None:
        if not isinstance(group, list):
            group = [group]
        group = (GROUP_IDS[g] if isinstance(g, str) else g for g in group)
        self.groups.extend(group)

    def packExtensionContent(self):
        return packU16List(self.groups, 2)
