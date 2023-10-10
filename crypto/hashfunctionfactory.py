#!/usr/bin/python3
# TODO own implementation of the most important hashes

import hashlib
from typing import Callable

class HashFunctionFactory:
    def create(self, hash_name: str) -> Callable|None:
        hash_function = None
        hash_name = hash_name.lower()
        if hash_name in hashlib.algorithms_available:
            hash_function = getattr(hashlib, hash_name)
        if hash_function is None:
            raise NotImplementedError(f'Hash type "{hash_name}" is not supported')
        return hash_function

hash_function_factory = HashFunctionFactory()

# To create hash functions
# Hash function returns an object, having the following methods
# .name: name of 
# .digest_size: The size of the resulting hash in bytes.
# .block_size: The internal block size of the hash algorithm in bytes.
# .digest(): Return the digest of the strings passed to the update() method so far. 
# .hexdigest(): Like digest() except the digest is returned as a string of double length, containing only hexadecimal digits.
# .update(arg): Update the hash object with the string arg.
