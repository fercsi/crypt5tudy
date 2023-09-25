#!/usr/bin/python3
# RFC5077

from .util import *
from .extension import Extension

class SessionTicket(Extension):
    def __init__(self):
        super().__init__()
        self.extensionType = 35

    def packExtensionContent(self):
        return b''
