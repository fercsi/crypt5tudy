#!/usr/bin/python3

#import os
import sys
import pyaes

def fail(text, *args, **kwargs):
    print("FAILED: "+text, *args, file=sys.stderr, **kwargs)
    sys.exit()

def main():
    print(pyaes.AES(b'\0'*16).encrypt("almaalmaalmaalma"))
#>    for i in dir(pyaes.AES(b'\0'*16).__dir__:
#>        print(i)
    return 0

main()
