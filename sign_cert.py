#!/usr/bin/python3
# TODO: commonName, space->_ /etc/ssl/certs/*.pem
# e.g. commonName: DST Root CA X3 -> /etc/ssl/certs/DST_Root_CA_X3.pem
# also check validity time

import hashlib
#import os
import sys
from util.pemasn1 import PemAsn1Object
from util.asn1 import *
from crypto.rsa import *

def load_cert(filename):
    with open(filename, 'r') as f:
        pem_content = f.read()
    pem_contents = pem_content.split('-\n-')
    for i in range(1, len(pem_contents)):
        pem_contents[i-1] += '-'
        pem_contents[i] = '-' + pem_contents[i]
    certs = []
    for pc in pem_contents:
        obj = PemAsn1Object()
        obj.import_pem(pc)
        c = obj.content
        key = c[0][6][1][0]
#>        print(c[0]._ber.hex())
        cert = {
            'key': {
                'size': key[0].value.bit_length(),
                'n': key[0].value,
                'e': key[1].value,
            },
            'tbsc': c[0]._ber,
            'algorithm': c[1],
            'signature': c[2]._raw[1:], # BIT STRING
            'issuer': extractInfo(c[0][3]),
            'subject': extractInfo(c[0][5]),
        }
        certs.append(cert)
    return certs

def extractInfo(obj):
    info = {}
    for s in obj:
        info[s[0][0].oid_name] = s[0][1].value
    return info

def digest(m):
#>    mb = Asn1BitString()
#>    mb.data = m
#>    mb.length = len(m)*8
#>    mb = Asn1.to_ber(mb)
    return hashlib.sha256(m).digest()

def encode(md, algorithm):
#>    return md
    # is this necessary in sha256WithRSAEncryption
    seq = Asn1Sequence()
    # oid "1.2.840.113549.2.9"
    algorithm = Asn1Sequence()
    algorithm.append(Asn1ObjectIdentifier('2.16.840.1.101.3.4.2.1'))
    algorithm.append(Asn1Null())

    seq.append(algorithm)
    seq.append(Asn1OctetString(md))
    return Asn1.to_ber(seq)

def decrypt_signature(ed, pubkey):
    rsa = Rsa()
    d = rsa._decrypt(RsaKey(pubkey['size'], pubkey['n'], pubkey['e']), ed)
    return d

def decode(d):
    obj = Asn1.from_ber(d)
    return obj[1].data

def fail(text, *args, **kwargs):
    print("FAILED: "+text, *args, file=sys.stderr, **kwargs)
    sys.exit()

def main():
    certs = load_cert(sys.argv[1])
    ci = 0
#>    print(certs)
    m = certs[ci]['tbsc']
#>    algorithm = certs[0]['algorithm']
    md1 = digest(m)
    print(len(md1)*8,md1.hex())
#>    d = encode(md, algorithm)
#>    print(len(d)*8,d.hex())
    d = decrypt_signature(certs[ci]['signature'], certs[ci+1]['key'])
#>    print(len(d)*8,d.hex())
#>    print(Asn1.from_ber(d))
    md2 = decode(d)
    print(len(md2)*8,md2.hex())
    if md1 == md2:
        print('Verification successfull')
    else:
        print('Verification failed')
    return 0

main()
