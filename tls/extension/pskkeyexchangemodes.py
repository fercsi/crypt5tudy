#!/usr/bin/python3
# RFC8446

from tls.util import *
from .extension import Extension

KEXMODE_IDS: dict[str, int] = {
    'psk_ke': 0,
    'psk_dhe_ke': 1,
    }

class PskKeyExchangeModes(Extension):
    def __init__(self, kexmodes: list[str|int]|None = None):
        super().__init__()
        self.extensionType = 45
        self.kexmodes = []
        if kexmodes:
            self.add(kexmodes)

    def add(self, kexmode: str|int|list) -> None:
        if not isinstance(kexmode, list):
            kexmode = [kexmode]
        kexmode = (KEXMODE_IDS[g.replace('-', '_').lower()]
                if isinstance(g, str) else g for g in kexmode)
        self.kexmodes.extend(kexmode)

    def packExtensionContent(self):
        return packU8List(self.kexmodes, 1)
