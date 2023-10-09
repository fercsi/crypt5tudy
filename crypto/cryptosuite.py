#!/usr/bin/python3

from .ciphersuite import *
from .hashfunctionfactory import hashFunctionFactory
from .aead import AEAD
from .aesgcm import AES_GCM
from .hkdf import HKDF

class CryptoSuite:
    def __init__(self, cipherSuite: int|str|CipherSuite):
        if isinstance(cipherSuite, int):
            self.cipherSuite = CIPHER_SUITE_BY_ID.get(cipherSuite)
        else:
            self.cipherSuite = CIPHER_SUITE_BY_NAME.get(cipherSuite)
        if self.cipherSuite is None:
            raise IndexError(f'Cipher Suite {cipherSuite} is unknown')
        self.setupCipherSuite()

    def setupCipherSuite(self):
        self.hashFunction = hashFunctionFactory.create(self.cipherSuite.hash)
        self.hkdf = HKDF(self.hashFunction)
        if self.cipherSuite.encryption == 'AES_GCM_13':
            self.aead = AES_GCM()
        else:
            raise NotImplementedError(f'Encryption {self.cipherSuite.encryption} is not implemented')
        self.keyLength = self.cipherSuite.kLen
        self.hashLength = self.hashFunction(b'').digest_size

    def setMyKey(self, key: bytes) -> None:
        self.aead.setMyKey(key)

    def setMyNonce(self, nonce: bytes) -> None:
        self.aead.setMyNonce(nonce)

    def setPeerKey(self, key: bytes) -> None:
        self.aead.setPeerKey(key)

    def setPeerNonce(self, nonce: bytes) -> None:
        self.aead.setPeerNonce(nonce)

    def encrypt(self, plainText: bytes, authData: bytes = b'') -> bytes:
        return self.aead.encrypt(plainText, authData)

    def decrypt(self, plainText: bytes, authData: bytes = b'', *, force=False) -> bytes:
        return self.aead.decrypt(plainText, authData)
