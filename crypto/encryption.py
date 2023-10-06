#!/usr/bin/python3

from abc import ABC, abstractmethod

class Encryption(ABC):
    def __init__(self, key: bytes = b''):
        self.setKey(key)

    def setKey(self, key: bytes) -> None:
        self.key = key

    @abstractmethod
    def encrypt(self, plainText: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, cipherText: bytes) -> bytes:
        pass

class NoEncryption(Encryption):

    def encrypt(self, plainText: bytes) -> bytes:
        return plainText

    def decrypt(self, cipherText: bytes) -> bytes:
        return cipherText
