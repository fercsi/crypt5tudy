#!/usr/bin/python3

from abc import ABC, abstractmethod
from util.function_meta import FunctionMeta

class BlockCipherMeta(FunctionMeta):
    def __new__(metacls, cls, bases, classdict, **kwargs):
        metacls._create_property(cls, bases, classdict, 'block_size')
        return super().__new__(metacls, cls, bases, classdict, **kwargs)

class BlockCipher(ABC, metaclass = BlockCipherMeta):
    block_size = 128

    def __init__(self, key: bytes|None = None):
        if key is not None:
            self.set_key(key)

    def set_key(self, key: bytes):
        self.key = key

    @abstractmethod
    def encrypt(self, plainText: bytes):
        pass

    def decrypt(self, cipherText: bytes):
        # Often encrypt and decrypt is the same function
        return self.encrypt(cipherText)

class NoEncryption(BlockCipher):
    def encrypt(self, plainText: bytes):
        return plainText
