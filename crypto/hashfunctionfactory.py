#!/usr/bin/python3
# TODO own implementation of the most important hashes

import hashlib
from typing import Callable

class HashFunctionFactory:
    def create(self, hashName: str) -> Callable|None:
        hashFunction = None
        hashName = hashName.lower()
        if hashName in hashlib.algorithms_available:
            hashFunction = getattr(hashlib, hashName)
        if hashFunction is None:
            raise NotImplementedError(f'Hash type "{hashName}" is not supported')
        return hashFunction

hashFunctionFactory = HashFunctionFactory()

# To create hash functions
# Hash function returns an object, having the following methods
# .name: name of 
# .digest_size: The size of the resulting hash in bytes.
# .block_size: The internal block size of the hash algorithm in bytes.
# .digest(): Return the digest of the strings passed to the update() method so far. 
# .hexdigest(): Like digest() except the digest is returned as a string of double length, containing only hexadecimal digits.
# .update(arg): Update the hash object with the string arg.
