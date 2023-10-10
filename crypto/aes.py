#!/usr/bin/python3
# TODO own implementation of AES128 and 256

import pyaes
from .encryption import Encryption

class AES(Encryption):
    def encrypt(self, plain_text: bytes) -> bytes:
        aes = pyaes.AES(self.key)
        cipher_text = aes.encrypt(plain_text)
        return cipher_text

    def decrypt(self, cipher_text: bytes) -> bytes:
        aes = pyaes.AES(self.key)
        plain_text = aes.decrypt(cipher_text)
        return plain_text
