#!/usr/bin/python3
# RFC7627 - no effect in TLS1.3

from tls.util import *
from .extension import Extension

class ExtendedMasterSecret(Extension):
    def __init__(self):
        super().__init__()
        self.extensionType = 23

    def packExtensionContent(self):
        return b''
