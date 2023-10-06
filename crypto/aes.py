#!/usr/bin/python3
# TODO own implementation of AES128 and 256

import pyaes
from .encryption import Encryption

class AES(Encryption):
    def encrypt(self, plainText: bytes) -> bytes:
        aes = pyaes.AES(self.key)
        cipherText = aes.encrypt(plainText)
        return cipherText

    def decrypt(self, cipherText: bytes) -> bytes:
        aes = pyaes.AES(self.key)
        plainText = aes.decrypt(cipherText)
        return plainText
