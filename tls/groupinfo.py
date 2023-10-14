#!/usr/bin/python3

from typing import NamedTuple

class WeierstrassGroup(NamedTuple):
    id: int
    idstr: str
    bits: int
    p: int
    a: int
    b: int
    Gx: int
    Gy: int
    n: int
    h: int

class MontgomeryGroup(NamedTuple):
    id: int
    idstr: str
    bits: int
    p: int
    A: int
    order: int
    cofactor: int
    U_P: int
    V_P: int

class FFDHGroup(NamedTuple):
    id: int
    idstr: str

GROUP_INFO_BY_ID: dict[int, object] = {
    # SEC 2: Recommended Elliptic Curve Domain Parameters",
    # Standards for Efficient Cryptography 2 (SEC 2), Version 2.0, January 2010,
    # http://www.secg.org/sec2-v2.pdf
    0x0017: WeierstrassGroup(
        id = 0x0017,
        idstr = 'secp256r1',
        bits = 256,
        p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        h = 0x1,
        ),
    0x0018: WeierstrassGroup(
        id = 0x0018,
        idstr = 'secp384r1',
        bits = 384,
        p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        Gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        Gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        n = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        h = 0x1,
        ),
    0x0019: WeierstrassGroup(
        id = 0x0019,
        idstr = 'secp521r1',
        bits = 521,
        p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        a = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc,
        b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        Gx = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        Gy = 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
        n = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
        h = 0x1,
        ),
    # RFC7748
    0x001d: MontgomeryGroup(
        id = 0x001d,
        idstr = 'x25519',
        bits = 255,
        p = 2**255 - 19,
        A = 486662,
        order = 2**252 + 0x14def9dea2f79cd65812631a5cf5d3ed,
        cofactor = 8,
        U_P = 9,
        V_P = 14781619447589544791020593568409986887264606134616475288964881837755586237401,
        ),
    0x001e: MontgomeryGroup(
        id = 0x001e,
        idstr = 'x448',
        bits = 448,
        p = 2**448 - 2**224 - 1,
        A = 156326,
        order = 2**446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d,
        cofactor = 4,
        U_P = 5,
        V_P = 355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362,
        ),
    # RFC7919
    0x0100: FFDHGroup(
        id = 0x0100,
        idstr = 'ffdhe2048',
        ),
    0x0101: FFDHGroup(
        id = 0x0101,
        idstr = 'ffdhe3072',
        ),
    0x0102: FFDHGroup(
        id = 0x0102,
        idstr = 'ffdhe4096',
        ),
    0x0103: FFDHGroup(
        id = 0x0103,
        idstr = 'ffdhe6144',
        ),
    0x0104: FFDHGroup(
        id = 0x0104,
        idstr = 'ffdhe8192',
        ),
    }

GROUP_INFO_BY_STR = {}
for id, cs in GROUP_INFO_BY_ID.items():
    GROUP_INFO_BY_STR[cs.idstr] = cs
