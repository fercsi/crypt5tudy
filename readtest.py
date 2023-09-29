#!/usr/bin/python3

import sys
import tls
import ecdh

if len(sys.argv) > 1:
    fname = sys.argv[1]
else:
    fname = 'tmp/clienthello' 
with open(fname,'rb') as f:
    content = f.read()
    r = tls.unpackRecord(content)
    print(r)

