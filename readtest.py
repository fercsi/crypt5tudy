#!/usr/bin/python3

import sys
import tls
import ecdh

with open('clienthello','rb') as f:
    content = f.read()
    r = tls.unpackRecord(content)
    print(r)

