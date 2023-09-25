#!/usr/bin/python3

import struct
from random import randint

def randomBytes(size: int) -> bytes:
    return bytes(randint(0,255) for _ in range(size))

# Pack constructs

def packInt(content: int, size: int) -> bytes:
    return content.to_bytes(size, 'big')

def packU8(content: int) -> bytes:
    return bytes([content])

def packU16(content: int) -> bytes:
    return content.to_bytes(2, 'big')

def packStr(content: str, size: int) -> bytes:
    data = content.encode()
    return packInt(len(data), size) + data

def packBytes(content: bytes, size: int) -> bytes:
    data = content
    return packInt(len(data), size) + data

def packU8List(content: list[int], size: int) -> bytes:
    if content:
        data = struct.pack(f'>{len(content)}B', *content)
    else:
        data = b''
    return packInt(len(data), size) + data

def packU16List(content: list[int], size: int) -> bytes:
    if content:
        data = struct.pack(f'>{len(content)}H', *content)
    else:
        data = b''
    return packInt(len(data), size) + data

def packBytesList(content: list[bytes], size: int) -> bytes:
    data = b''.join(content)
    return packInt(len(data), size) + data

# Unpack constructs

def unpackInt(raw: bytes, pos: int, size: int) -> int:
    return int.from_bytes(raw[pos:pos+size], 'big')

def unpackU8(raw: bytes, pos: int) -> int:
    return int(raw[pos])

def unpackU16(raw: bytes, pos: int) -> int:
    return int.from_bytes(raw[pos:pos+2], 'big')

def unpackStr(raw: bytes, pos: int, size: int) -> str:
    length = unpackInt(raw, pos, size)
    data = raw[pos+size:pos+size+length]
    return data.encode()

def unpackBytes(raw: bytes, pos: int, size: int) -> bytes:
    length = unpackInt(raw, pos, size)
    data = raw[pos+size:pos+size+length]
    return data

def unpackU8List(raw: bytes, pos: int, size: int) -> list[int]:
    length = unpackInt(raw, pos, size)
    if length == 0:
        return []
    data = raw[pos+size:pos+size+length]
    return list(struct.unpack(f'>{len(content)}B', *data))

def unpackU16List(raw: bytes, pos: int, size: int) -> list[int]:
    length = unpackInt(raw, pos, size)
    if length == 0:
        return []
    data = raw[pos+size:pos+size+length]
    return list(struct.unpack(f'>{len(content)}H', *data))
