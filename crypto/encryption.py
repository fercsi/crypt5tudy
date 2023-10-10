#!/usr/bin/python3

from abc import ABC, abstractmethod

class Encryption(ABC):
    def __init__(self, key: bytes = b''):
        self.set_key(key)

    def set_key(self, key: bytes) -> None:
        self.key = key

    @abstractmethod
    def encrypt(self, plain_text: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, cipher_text: bytes) -> bytes:
        pass

class NoEncryption(Encryption):

    def encrypt(self, plain_text: bytes) -> bytes:
        return plain_text

    def decrypt(self, cipher_text: bytes) -> bytes:
        return cipher_text
