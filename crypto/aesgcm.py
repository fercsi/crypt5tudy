#!/usr/bin/python3

from .aead import AEAD
from .aes import AES
from .gcm import GCM

class AES_GCM(AEAD):
    def encryptMessage(self, plainText: bytes, authData: bytes, nonce: bytes) -> (bytes, bytes):
        gcm = GCM(AES(self.myKey))
        return gcm.encrypt(plainText, authData, nonce)

    def decryptMessage(self, cipherText: bytes, authData: bytes, nonce: bytes) -> (bytes, bytes):
        gcm = GCM(AES(self.peerKey))
        return gcm.decrypt(cipherText, authData, nonce)
