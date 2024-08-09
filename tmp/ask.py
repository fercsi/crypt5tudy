#!/usr/bin/python3
# https://doi.org/10.6028/NIST.SP.800-38D

import pyaes

def aes(key, plain_text: bytes) -> bytes:
    aes = pyaes.AESModeOfOperationECB(key)
    cipher_text = aes.encrypt(plain_text)
    return cipher_text

#>def polymul(a: int, b: int):
#>    p = sum(1<<n for n in [0,1,2,7,128])
#>    mask = 1 << 128
#>    result = 0
#>    while b:
#>        if b & 1:
#>            result ^= a
#>        a <<= 1
#>        if a & mask:
#>            a ^= p
#>        b >>= 1
#>    return result

def polymul(a: int, b: int):
    p = sum(1<<(127-n) for n in [0,1,2,7])
#>    print(f'!!! {p:x}')
    result = 0
#>    print(f'--------------')
#>    print(f'{p:0>32x}')
#>    print(f'{a:0>32x}')
#>    print(f'{b:0>32x}')
    for i in range(128):
        if b & (1<<127):
            result ^= a
        if a & 1:
            a = (a >> 1) ^ p
        else:
            a >>= 1
        b <<= 1
#>        print(f'    {result:0>32x}')
#>    print(f'{result:0>32x}')
    return result

def ghash(x: bytes) -> bytes:
    global H
    yi = 0
    for pos in range(0, len(x), 16):
        b = (x[pos:pos+16] + b'\0' * 15)[:16]
#>        print(f'{b.hex()} $$$')
        xi = int.from_bytes((x[pos:pos+16] + b'\0' * 15)[:16], 'big')
        yi = polymul((yi ^ xi), H)
    return yi.to_bytes(16, 'big')

key = bytes.fromhex('9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f')
iv = bytes.fromhex('9563bc8b590f671f488d2da3')
H = int.from_bytes(aes(key, b'\0' * 16), 'big')
# skip cipher_text creation, because it works
AC = bytes.fromhex(
      '17030300170000000000000000000000' # auth data
    + '6be02f9da7c2dc000000000000000000' # cipher text
    + '0000000000000028' + '0000000000000038' # len(A), len(C)
    )
S = ghash(AC)
J0 = iv + (1).to_bytes(4, 'big')
T = bytes(x^y for x, y in zip(S, aes(key,J0)))
print('Expected:   9ddef56f2468b90adfa25101ab0344ae')
print('Calculated:', T.hex())

#>I  try to  understand  AEAD authentication  tag  evaluation in  AES-GCM.
#>I  implemented  GCM.  Cipher  text  is  created  as  expected,  but  the
#>authentication tag is different from the received one.
#>
#>this is the received record:
#>
#>```
#>17 03 03 00 17
#>6b e0 2f 9d a7 c2 dc
#>9d de f5 6f 24 68 b9 0a df a2 51 01 ab 03 44 ae
#>```
#>
#>plain text is:
#>
#>```
#>08 00 00 02 00 00 16
#>```
#>
#>Cipher is TLS_AES_256_GCM_SHA384.  Parameters can be seen  in the source
#>code below.  I tried to  remove the unnecessary  code parts, so  that it
#>still runs. I  took out the cipher creation, only  the auth tag creation
#>remained. Do you know where is my mistake? Probably I misunderstood some
#>part of the specification(s).
