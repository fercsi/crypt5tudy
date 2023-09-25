#!/usr/bin/python3
# RFC4366

class Extension:
    def __init__(self):
        self.extensionType = 0xfafa

    def pack(self):
        type = self.extensionType.to_bytes(2, 'big')
        content = self.packExtensionContent()
        length = len(content).to_bytes(2, 'big')
        return type + length + content

    def packExtensionContent(self):
        return b''

