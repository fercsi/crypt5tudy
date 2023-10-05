#!/usr/bin/python3

import pyaes
from .encryption import Encryption

class AES(Encryption):
    def encrypt(self, plainText: bytes) -> bytes:
        aes = pyaes.AESModeOfOperationECB(self.key)
        cipherText = aes.encrypt(plainText)
        return cipherText

    def decrypt(self, cipherText: bytes) -> bytes:
        aes = pyaes.AESModeOfOperationECB(self.key)
        plainText = aes.encrypt(cipherText)
        return plainText
