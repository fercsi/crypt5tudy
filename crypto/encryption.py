#!/usr/bin/python3

class Encryption:
    def __init__(self, key: bytes = b''):
        self.setKey(key)

    def setKey(self, key: bytes) -> None:
        self.key = key

    def encrypt(self, plainText: bytes) -> bytes:
        return plainText

    def decrypt(self, cipherText: bytes) -> bytes:
        return cipherText
