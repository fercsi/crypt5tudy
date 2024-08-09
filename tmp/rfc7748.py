#!/usr/bin/python3
# RFC 7748 implementation of Curve 25519

from modular import Modular

p = 2**255 - 19
A = 486662
bits = 255
order = 2**252 + 0x14def9dea2f79cd65812631a5cf5d3ed
cofactor = 8
UP = 9
VP = 14781619447589544791020593568409986887264606134616475288964881837755586237401
base = (UP, VP)

#(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
#(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))

def decode_little_endian(b, bits=255):
    return sum([b[i] << 8*i for i in range((bits+7)//8)])

def decode_ucoordinate(u, bits=255):
    u_list = [b for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1<<(bits%8))-1
    return decode_little_endian(u_list, bits)

def encode_ucoordinate(u, bits=255):
    u = u % p
#>    return b''.join([chr((u >> 8*i) & 0xff)
#>                    for i in range((bits+7)//8)])
    return bytearray([ (u >> 8*i) & 0xff for i in range((bits+7)//8) ])

def decode_scalar25519(k):
    k_list = [b for b in k]
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decode_little_endian(k_list, 255)

def ec_mul(k, u):
    global A, p, bits
#>    k = decode_scalar25519(k)
#>    u = decode_ucoordinate(u, bits)
#>    p = 2**255 - 19
    a24 = (A - 2) >> 2

    M = Modular(p)
    x_1 = M(u)
    x_2 = M(1)
    z_2 = M(0)
    x_3 = M(u)
    z_3 = M(1)
    swap = 0

    for t in range(bits-1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        (x_2, x_3) = cswap(swap, x_2, x_3)
        (z_2, z_3) = cswap(swap, z_2, z_3)
        swap = k_t

        A = x_2 + z_2
        AA = A**2
        B = x_2 - z_2
        BB = B**2
        E = AA - BB
        C = x_3 + z_3
        D = x_3 - z_3
        DA = D * A
        CB = C * B
        x_3 = (DA + CB)**2
        z_3 = x_1 * (DA - CB)**2
        x_2 = AA * BB
        z_2 = E * (AA + a24 * E)

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    res = x_2 * (z_2**(p - 2))
#>    return encode_ucoordinate(int(res), bits)
    return res

def cswap(swap, x_2, x_3):
    """Swap two values in constant time"""
#>    index = int(swap) * 2
#>    temp = (x_2, x_3, x_3, x_2)
#>    return temp[index:index+2]
    temp = (x_2, x_3,  x_2)
    return temp[swap:swap+2]

def main():
#>    k = 0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
#>    u = 0xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
#>    k = 0xc49a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346a5
#>    u = 0x4c1cabd0a603a9103b35b326ec2466727c5fb124a4c19435db3030586768dbe6
#>    k = 0x4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
#>    u = 0xe5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
#>    k = 0x0dba18799e16a42cd401eae021641bc1f56a7d959126d25a3c67b4d1d4e9664b
#>    u = 0x93a415c749d54cfc3e3cc06f10e7db312cae38059d95b7f4d3116878120f21e5
#>    k = 31029842492115040904895560451863089656472772604678260265531221036453811406496
#>    u = 34426434033919594451155107781188821651316167215306631574996226621102155684838

    k = b'\xa5\x46\xe3\x6b\xf0\x52\x7c\x9d\x3b\x16\x15\x4b\x82\x46\x5e\xdd\x62\x14\x4c\x0a\xc1\xfc\x5a\x18\x50\x6a\x22\x44\xba\x44\x9a\xc4'
    u = b'\xe6\xdb\x68\x67\x58\x30\x30\xdb\x35\x94\xc1\xa4\x24\xb1\x5f\x7c\x72\x66\x24\xec\x26\xb3\x35\x3b\x10\xa9\x03\xa6\xd0\xab\x1c\x4c'

    k = decode_scalar25519(k)
    u = decode_ucoordinate(u, 255)

    print(hex(k))
    print(k)
    print(hex(u))
    print(u)
    u2 = int(ec_mul(k, u))
    print(hex(u2))
    u2 = encode_ucoordinate(u2, bits)
    print(''.join(f'{b:0>2x}' for b in u2))


if __name__ == "__main__":
    main()
