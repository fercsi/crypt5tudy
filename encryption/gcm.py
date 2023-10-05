#!/usr/bin/python3
# ONLY TLS1.3 Support! 

from polynomial import Polynomial
from encryption import Encryption

class GCM:
    poly: Polynomial
    encryption: Encryption
    myDerivedIV: bytes
    myRecordIV: bytes
    myRecSeqNum: int
    yourDerivedIV: bytes
    yourRecordIV: bytes
    yourRecSeqNum: int

    def __init__(self, encryption: Encryption):
        self.poly = Polynomial([128, 7, 2, 1, 0], reverse=True)
        self.encryption = encryption
        self.h = self.poly(int.from_bytes(encryption.encrypt(b'\0'*16), 'big'))

    def setMyIV(self, iv: bytes):
        iv = self.normalizeIV(iv)
        self.myDerivedIV = iv
        self.myRecordIV = iv
        self.myRecSeqNum = 0

    def setYourIV(self, iv: bytes):
        iv = self.normalizeIV(iv)
        self.yourDerivedIV = iv
        self.yourRecordIV = iv
        self.yourRecSeqNum = 0

    def normalizeIV(self, iv: bytes) -> (bytes, int):
        if len(iv) == 12:
            return iv
        # TODO: move TLS1.3 related parts outside this file (following calculation has been tested)
#>        u = (-len(iv)) % 16
#>        iv = self.ghash(iv + (b'\0' * u) + (len(iv) * 8).to_bytes(16, 'big')).hex()
        raise NotImplementedError('Currently only 96 bit IV-s are supported')

    def encrypt(self, plainText: bytes, authData: bytes) -> (bytes, bytes):
        iv = self.myRecordIV
        self.myRecSeqNum += 1
        xored = self.myRecSeqNum ^ int.from_bytes(self.myRecordIV, 'big')
        self.myRecordIV = xored.to_bytes(12, 'big')
        p = plainText
        c = self.gctr(iv, 2, p)
        u = (-len(c)) % 16
        v = (-len(authData)) % 16
        # length is in bits (not documented in RFC):
        s = self.ghash(authData + (b'\0' * v) + c + (b'\0' * u)
            + (len(authData)*8).to_bytes(8, 'big') + (len(c)*8).to_bytes(8, 'big'))
        t = self.gctr(iv, 1, s)[:16]
        return c, t

    def decrypt(self, cipherText: bytes, authData: bytes) -> (bytes, bytes):
        iv = self.yourRecordIV
        self.yourRecSeqNum += 1
        xored = self.yourRecSeqNum ^ int.from_bytes(self.yourRecordIV, 'big')
        self.yourRecordIV = xored.to_bytes(12, 'big')
        c = cipherText
        p = self.gctr(iv, 2, c)
        u = (-len(c)) % 16
        v = (-len(authData)) % 16
        s = self.ghash(authData + (b'\0' * v) + c + (b'\0' * u)
            + (len(authData)*8).to_bytes(8, 'big') + (len(c)*8).to_bytes(8, 'big'))
        t = self.gctr(iv, 1, s)[:16]
        return p, t

    def ghash(self, x: bytes) -> bytes:
        _P = self.poly
        h = self.h
        yi = _P(0)
        for pos in range(0, len(x), 16):
            xi = _P(int.from_bytes((x[pos:pos+16] + b'\0' * 15)[:16], 'big'))
            yi = (yi ^ xi) * h
        return yi.value.to_bytes(16, 'big')

    def gctr(self, icbNonce: bytes, icbCtr: int, x: bytes) -> bytes:
        y = []
        for pos in range(0, len(x), 16):
            xi = x[pos:pos+16]
            key = self.encryption.encrypt(icbNonce + icbCtr.to_bytes(4, 'big'))
            xored = bytes(x^y for x, y in zip(xi, key))
            y.append(xored)
            icbCtr += 1
        return b''.join(y)
