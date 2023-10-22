#!/usr/bin/python3

from secrets import token_bytes

def random_bytes(size: int) -> bytes:
    return token_bytes(size)
