#!/usr/bin/python3

#import os
import sys
import crypto.hash

def fail(text, *args, **kwargs):
    print("FAILED: "+text, *args, file=sys.stderr, **kwargs)
    sys.exit()

def main():
    h = crypto.hash.xor8(b'abcde')
    print(h.name)
    print(h.digest_size)
    print(h.block_size)
    print(h.hexdigest())
    print(h.digest())
    return 0

main()
