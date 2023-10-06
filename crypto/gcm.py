#!/usr/bin/python3

from polynomial import Polynomial
from .encryption import Encryption

class GCM:
    poly: Polynomial
    encryption: Encryption

    def __init__(self, encryption: Encryption):
        self.poly = Polynomial([128, 7, 2, 1, 0], reverse=True)
        self.encryption = encryption
        self.h = self.poly(int.from_bytes(encryption.encrypt(b'\0'*16), 'big'))

    def nonceToIV(self, nonce: bytes):
        if len(nonce) == 12:
            iv = nonce + b'\0\0\0\1'
        else:
            u = (-len(nonce)) % 16
            iv = self.ghash(nonce + (b'\0' * u)
                                + (len(nonce) * 8).to_bytes(16, 'big'))
        return int.from_bytes(iv)

    def encrypt(self, plainText: bytes, authData: bytes, nonce: bytes) -> (bytes, bytes):
        iv = self.nonceToIV(nonce)
        p = plainText
        c = self.gctr(iv + 1, p)
        u = (-len(c)) % 16
        v = (-len(authData)) % 16
        # length is in bits (not documented in RFC):
        s = self.ghash(authData + (b'\0' * v) + c + (b'\0' * u)
            + (len(authData)*8).to_bytes(8, 'big') + (len(c)*8).to_bytes(8, 'big'))
        t = self.gctr(iv, s)[:16]
        return c, t

    def decrypt(self, cipherText: bytes, authData: bytes, nonce: bytes) -> (bytes, bytes):
        iv = self.nonceToIV(nonce)
        c = cipherText
        p = self.gctr(iv + 1, c)
        u = (-len(c)) % 16
        v = (-len(authData)) % 16
        s = self.ghash(authData + (b'\0' * v) + c + (b'\0' * u)
            + (len(authData)*8).to_bytes(8, 'big') + (len(c)*8).to_bytes(8, 'big'))
        t = self.gctr(iv, s)[:16]
        return p, t

    def ghash(self, x: bytes) -> bytes:
        _P = self.poly
        h = self.h
        yi = _P(0)
        for pos in range(0, len(x), 16):
            xi = _P(int.from_bytes((x[pos:pos+16] + b'\0' * 15)[:16], 'big'))
            yi = (yi ^ xi) * h
        return yi.value.to_bytes(16, 'big')

    def gctr(self, icb: int, x: bytes) -> bytes:
        y = []
        for pos in range(0, len(x), 16):
            xi = x[pos:pos+16]
            key = self.encryption.encrypt(icb.to_bytes(16, 'big'))
            xored = bytes(x^y for x, y in zip(xi, key))
            y.append(xored)
            icb += 1
        return b''.join(y)
