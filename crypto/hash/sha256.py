#!/usr/bin/python3
# According to FIPS 180-2

import struct
from .hashfunction import HashFunction

class sha256(HashFunction):
    digest_size: int = 32

    _M: bytearray
    _l: int
    _H: list[int]

    def init(self) -> None:
        self._M = bytearray()
        self._l = 0
        self._H = _H0.copy()

    def update(self, message: bytes) -> None:
        self._M += message
        while len(self._M) >= 64:
            M = self._M[:64]
            self._M = self._M[64:]
            self._l += 512
            self._H = self._compute_hash(self._H, M)

    def digest(self) -> bytes:
        li = len(self._M)
        M = self._M.copy()
        H = self._H
        l = self._l + li * 8
        if li < 56:
            M += b'\x80' + b'\0' * (55-li)
        else: # always < 64!
            M += b'\x80' + b'\0' * (63-li)
            H = self._compute_hash(H, M)
            M = b'\0' * 56
        M += l.to_bytes(8, 'big')
        H = self._compute_hash(H, M)
        return struct.pack('>' + 'I'*8, *H)

    def _compute_hash(self, H: list[int], M: bytearray) -> list[int]:
        bitmask = ((1 << 32) - 1)
        # step 1
        W = list(struct.unpack('>' + 'I'*16, M)) + [0] * 48
        for t in range(16, 64):
            W[t] = (_sigma_1(W[t - 2]) + W[t - 7] + _sigma_0(W[t - 15]) + W[t - 16]) & bitmask

        # step 2
        (a, b, c, d, e, f, g, h) = H

        # step 3
        for i in range(64):
            T1 = h + _SIGMA_1(e) + _Ch(e, f, g) + _K[i] + W[i]
            T2 = _SIGMA_0(a) + _Maj(a, b, c)
            h = g
            g = f
            f = e
            e = (d + T1) & bitmask
            d = c
            c = b
            b = a
            a = (T1 + T2) & bitmask

        # step 4
        Q = [a, b, c, d, e, f, g, h]
        H = [h + q & bitmask for h, q in zip(H, Q)]

        return H

_H0: list[int] = [
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    ]
_K: list[int] = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ]

def _ROTL(x, n):
    return (x << n | x >> 32 - n) & (1 << 32) - 1
def _ROTR(x, n):
    return (x >> n | x << 32 - n) & (1 << 32) - 1

def _Ch(x, y, z): # (4.2)
    return x & y ^ ~x & z
def _Maj(x, y, z): # (4.3)
    return x & y ^ x & z ^ y & z

def _SIGMA_0(x): # (4.4)
    return _ROTR(x, 2) ^ _ROTR(x, 13) ^ _ROTR(x, 22)
def _SIGMA_1(x): # (4.5)
    return _ROTR(x, 6) ^ _ROTR(x, 11) ^ _ROTR(x, 25)

def _sigma_0(x): # (4.6)
    return _ROTR(x, 7) ^ _ROTR(x, 18) ^ x >> 3
def _sigma_1(x): # (4.7)
    return _ROTR(x, 17) ^ _ROTR(x, 19) ^ x >> 10
