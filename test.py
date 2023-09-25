#!/usr/bin/python3

#import os
import sys
import ec
import ecdh
from modular import Modular

def modtest():
    M = Modular(37)
    v1 = M(27)
    v2 = M(31)
#>    v3 = v1 + v2
#>    v4 = 1 / v2
    print(v1+v2)
    print(v1-v2)
    print(v1*v2)
    print(v1.inverse())
    print(v1/v2)
    print(v1.value/v2)
    print(v1**v2.value)
    print(v1.sqrt())

    M = Modular(2**255-19)
    print(M(1).sqrt())
#>    print(f'{v4:x}')
#>    print(m.add(4, 5))
#>    print(m.sub(4, 5))
#>    print(m.mul(4, 5))
#>    print(m.inv(4))
#>    print(m.div(4, 5))
#>    print(m.pow(4, 5))
#>    print(m.sqrt(4))

def ectest():
    k = 31029842492115040904895560451863089656472772604678260265531221036453811406496
    u = 34426434033919594451155107781188821651316167215306631574996226621102155684838
    e = ec.EC25519(u)
    m = k * e
    print(type(e))
    print(type(m))
    print(int(m))
    print(hex(int(m)))
#>    e = ec.Weierstrass(37, 0, 7)
#>    p = e.xToPoint(6)
#>    q = e.xToPoint(8)
#>    r = e.add(p, q)
#>    print(p, q, r)

def showBytes(bs):
    print(''.join(f'{b:0>2x}' for b in bs))

def dhtest():
    k = b'\xa5\x46\xe3\x6b\xf0\x52\x7c\x9d\x3b\x16\x15\x4b\x82\x46\x5e\xdd\x62\x14\x4c\x0a\xc1\xfc\x5a\x18\x50\x6a\x22\x44\xba\x44\x9a\xc4'
    u = b'\xe6\xdb\x68\x67\x58\x30\x30\xdb\x35\x94\xc1\xa4\x24\xb1\x5f\x7c\x72\x66\x24\xec\x26\xb3\x35\x3b\x10\xa9\x03\xa6\xd0\xab\x1c\x4c'
    u2 = ecdh.x25519(k, u)
    showBytes(u2)
#>    g = b'\t' + b'\0'*31
#>    k1 = b'\x01' + b'\0'*31
#>    p1 = ecdh.x25519(g, g)
#>    showBytes(p1)
    k = b'\t' + b'\0'*31
    u = k
    for i in range(1,1001):
        u2 = ecdh.x25519(k, u)
        if i in [1,1000,1_000_000]:
            showBytes(u2)
        u = k
        k = u2

def kextest():
    apri = b'\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a'
    bpri = b'\x5d\xab\x08\x7e\x62\x4a\x8a\x4b\x79\xe1\x7f\x8b\x83\x80\x0e\xe6\x6f\x3b\xb1\x29\x26\x18\xb6\xfd\x1c\x2f\x8b\x27\xff\x88\xe0\xeb'
    chk = b'\x4a\x5d\x9d\x5b\xa4\xce\x2d\xe1\x72\x8e\x3b\xf4\x80\x35\x0f\x25\xe0\x7e\x21\xc9\x47\xd1\x9e\x33\x76\xf0\x9b\x3c\x1e\x16\x17\x42'
    g = (9).to_bytes(32, 'little')
    apub = ecdh.x25519(apri, g)
    bpub = ecdh.x25519(bpri, g)
    sec1 = ecdh.x25519(apri, bpub)
    sec2 = ecdh.x25519(bpri, apub)
    showBytes(chk)
    showBytes(sec1)
    showBytes(sec2)

    apri, apub = ecdh.generateKeyPairX25519()
    bpri, bpub = ecdh.generateKeyPairX25519()
    sec1 = ecdh.createSecret(apri, bpub)
    sec2 = ecdh.createSecret(bpri, apub)
    showBytes(sec1)
    showBytes(sec2)



def main():
#>    modtest()
#>    ectest()
#>    dhtest()
    kextest()
    return 0

main()
