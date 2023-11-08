#!/usr/bin/python3

import sys
from crypto.rsa import Rsa
from util.asn1 import *
from util.pem import *

def fail(errstr: str|None = None):
    if errstr is not None:
        print(errstr, file=sys.stderr)
    print(f"Usage: {sys.argv[0]} [TYPE] [PARAM]", file=sys.stderr)
    sys.exit(1)

def create_rsa_key(size: int):
    r = Rsa(size)
    if size < 17:
        r.default_e = 3
    r.generate_key_pair()
    pk = r.my_private_key
    asn = Asn1Sequence()
    asn.append(Asn1Integer(0)) # version
    asn.append(Asn1Integer(pk.n))
    asn.append(Asn1Integer(pk.e))
    asn.append(Asn1Integer(pk.d))
    asn.append(Asn1Integer(pk.p))
    asn.append(Asn1Integer(pk.q))
    asn.append(Asn1Integer(pk.dp))
    asn.append(Asn1Integer(pk.dq))
    asn.append(Asn1Integer(pk.qinv))
    ber_content = Asn1.to_ber(asn)
    pem_text = Pem.create('RSA PRIVATE KEY', ber_content)
    return pem_text

def main():
    key_type = 'rsa'
    key_param = 2048
    if len(sys.argv) >= 2:
        if sys.argv[1] in ('-h', '--help'):
            fail()
        key_type = sys.argv[1]
        if key_type == 'rsa':
            key_param = 2048
        else:
            fail("Key type not supported")
    if len(sys.argv) >= 3:
        key_param = int(sys.argv[2])
    if key_type == 'rsa':
        key = create_rsa_key(key_param)
    print(key, end='')
    return 0

main()
