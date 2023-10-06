#!/usr/bin/python3

from abc import ABC, abstractmethod

class AEAD:
    """AEAD abstract class

    Currently only TLS1.3 functionality is implemented
    """
    tlsVersion: int
    myNonce: int # int, so calculations are easier with them
    myRecSeqNum: int
    peerNonce: int
    peerRecSeqNum: int
    
    def __init__(self, *, tlsVersion: str = 0x0304) -> None:
        if tlsVersion != 0x0304:
            raise NotImplementedError("Selected version is not supported by AEAD")
        self.tlsVersion = tlsVersion

    def setMyKey(self, key: bytes) -> None:
        self.myKey = key

    def setPeerKey(self, key: bytes) -> None:
        self.peerKey = key

    def setMyNonce(self, nonce: bytes) -> None:
        self.myNonce = int.from_bytes(nonce, 'big')
        self.myRecSeqNum = 0

    def setPeerNonce(self, nonce: bytes) -> None:
        self.peerNonce = int.from_bytes(nonce, 'big')
        self.peerRecSeqNum = 0

    def encrypt(self, plainText: bytes, authData: bytes) -> (bytes, bytes):
        nonce = (self.myNonce ^ self.myRecSeqNum).to_bytes(12, 'big')
        cipherText, authTag = self.encryptMessage(plainText, authData, nonce)
        self.myRecSeqNum += 1
        return cipherText, authTag

    def decrypt(self, cipherText: bytes, authData: bytes) -> (bytes, bytes):
        nonce = (self.peerNonce ^ self.peerRecSeqNum).to_bytes(12, 'big')
        plainText, authTag = self.decryptMessage(cipherText, authData, nonce)
        self.peerRecSeqNum += 1
        return plainText, authTag
