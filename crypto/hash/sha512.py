#!/usr/bin/python3
# According to FIPS 180-2

import struct
from .hashfunction import HashFunction
from .registry import Registry

class sha512(HashFunction):
    # 6.3
    digest_size: int = 64
    block_size: int = 128

    _M: bytearray
    _l: int
    _H: list[int]

    def init(self) -> None:
        self._M = bytearray()
        self._l = 0
        self._H = _H0[self.name].copy()

    def update(self, message: bytes) -> None:
        self._M += message
        while len(self._M) >= 128:
            M = self._M[:128]
            self._M = self._M[128:]
            self._l += 1024
            self._H = self._compute_hash(self._H, M)

    def digest(self) -> bytes:
        li = len(self._M)
        M = self._M.copy()
        H = self._H
        l = self._l + li * 8
        if li < 112:
            M += b'\x80' + b'\0' * (111-li)
        else: # always < 128!
            M += b'\x80' + b'\0' * (127-li)
            H = self._compute_hash(H, M)
            M = b'\0' * 112
        M += l.to_bytes(16, 'big')
        H = self._compute_hash(H, M)
        return struct.pack('>' + 'Q'*8, *H)[:self.digest_size]

    def _compute_hash(self, H: list[int], M: bytearray) -> list[int]:
        # 6.3.2
        bitmask = ((1 << 64) - 1)
        # step 1
        W = list(struct.unpack('>' + 'Q'*16, M)) + [0] * 64
        for t in range(16, 80):
            W[t] = (_sigma_1(W[t - 2]) + W[t - 7] + _sigma_0(W[t - 15]) + W[t - 16]) & bitmask

        # step 2
        (a, b, c, d, e, f, g, h) = H

        # step 3
        for i in range(80):
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


class sha384(sha512):
    digest_size: int = 48


_H0: list[int] = {
    'sha384': [ # 5.3.3
        0xcbbb9d5dc1059ed8,0x629a292a367cd507,0x9159015a3070dd17,0x152fecd8f70e5939,0x67332667ffc00b31,0x8eb44a8768581511,0xdb0c2e0d64f98fa7,0x47b5481dbefa4fa4,
        ],
    'sha512': [ # 5.3.4
        0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179,
        ],
    }
_K: list[int] = [ # 4.2.3
    0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
    0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
    0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
    0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
    0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
    0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
    0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
    0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
    0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
    0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
    0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
    0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
    0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817,
    ]

def _ROTL(x, n):
    return (x << n | x >> 64 - n) & (1 << 64) - 1
def _ROTR(x, n):
    return (x >> n | x << 64 - n) & (1 << 64) - 1

def _Ch(x, y, z): # (4.8)
    return x & y ^ ~x & z
def _Maj(x, y, z): # (4.9)
    return x & y ^ x & z ^ y & z

def _SIGMA_0(x): # (4.10)
    return _ROTR(x, 28) ^ _ROTR(x, 34) ^ _ROTR(x, 39)
def _SIGMA_1(x): # (4.11)
    return _ROTR(x, 14) ^ _ROTR(x, 18) ^ _ROTR(x, 41)

def _sigma_0(x): # (4.12)
    return _ROTR(x, 1) ^ _ROTR(x, 8) ^ x >> 7
def _sigma_1(x): # (4.13)
    return _ROTR(x, 19) ^ _ROTR(x, 61) ^ x >> 6

Registry.add(sha384)
Registry.add(sha512)
