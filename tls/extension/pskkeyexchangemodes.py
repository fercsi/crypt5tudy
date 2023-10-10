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
        self.extension_type = 45
        self.kexmodes = []
        if kexmodes:
            self.add(kexmodes)

    def add(self, kexmode: str|int|list) -> None:
        if not isinstance(kexmode, list):
            kexmode = [kexmode]
        kexmode = (KEXMODE_IDS[g.replace('-', '_').lower()]
                if isinstance(g, str) else g for g in kexmode)
        self.kexmodes.extend(kexmode)

    def pack_extension_content(self):
        return pack_u8_list(self.kexmodes, 1)

    def unpack_extension_content(self, raw):
        self.kexmodes = unpack_u8_list(raw, 0, 1)

    def represent(self, level: int = 0):
        text = super().represent(level);
        ind = '  '*level
        revlut = {}
        for k, v in KEXMODE_IDS.items():
            revlut[v] = k
        for v in self.kexmodes:
            t = revlut.get(v)
            if t is not None:
                text += ind + f'  - {t}\n'
            else:
                text += ind + f'  - unknown kexmode {t:0>4x}\n'
        return text
