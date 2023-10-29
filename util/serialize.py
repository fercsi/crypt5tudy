#!/usr/bin/python3

import struct

# Pack constructs

def pack_int(content: int, size: int|None = None) -> bytes:
    if size is not None:
        return content.to_bytes(size, 'big')
    h = hex(content)[2:]
    if len(h) & 1:
        h = '0' + h
    return bytes.fromhex(h)

def pack_u8(content: int) -> bytes:
    return bytes([content])

def pack_u16(content: int) -> bytes:
    return content.to_bytes(2, 'big')

def pack_u24(content: int) -> bytes:
    return content.to_bytes(3, 'big')

def pack_u32(content: int) -> bytes:
    return content.to_bytes(4, 'big')

def pack_str(content: str, size: int) -> bytes:
    data = content.encode()
    return pack_int(len(data), size) + data

def pack_bytes(content: bytes, size: int) -> bytes:
    data = content
    return pack_int(len(data), size) + data

def pack_u8_list(content: list[int], size: int) -> bytes:
    if content:
#>        data = struct.pack(f'>{len(content)}B', *content)
        data = bytes(content)
    else:
        data = b''
    return pack_int(len(data), size) + data

def pack_u16_list(content: list[int], size: int) -> bytes:
    if content:
        data = struct.pack(f'>{len(content)}H', *content)
    else:
        data = b''
    return pack_int(len(data), size) + data

def pack_bytes_list(content: list[bytes], size: int) -> bytes:
    data = b''.join(content)
    return pack_int(len(data), size) + data

# Unpack constructs

def unpack_int(raw: bytes, pos: int, size: int) -> int:
    return int.from_bytes(raw[pos:pos+size], 'big')

def unpack_u8(raw: bytes, pos: int = 0) -> int:
    return int(raw[pos])

def unpack_u16(raw: bytes, pos: int = 0) -> int:
    return int.from_bytes(raw[pos:pos+2], 'big')

def unpack_u24(raw: bytes, pos: int = 0) -> int:
    return int.from_bytes(raw[pos:pos+3], 'big')

def unpack_u32(raw: bytes, pos: int = 0) -> int:
    return int.from_bytes(raw[pos:pos+4], 'big')

def unpack_str(raw: bytes, pos: int, size: int) -> str:
    length = unpack_int(raw, pos, size)
    data = raw[pos+size:pos+size+length]
    return data.decode()

def unpack_bytes(raw: bytes, pos: int, size: int) -> bytes:
    length = unpack_int(raw, pos, size)
    data = raw[pos+size:pos+size+length]
    return data

def unpack_u8_list(raw: bytes, pos: int, size: int) -> list[int]:
    length = unpack_int(raw, pos, size)
    if length == 0:
        return []
    data = raw[pos+size:pos+size+length]
#>    return list(struct.unpack(f'>{len(data)}B', *data))
    return list(data)

def unpack_u16_list(raw: bytes, pos: int, size: int) -> list[int]:
    length = unpack_int(raw, pos, size)
    if length == 0:
        return []
    data = raw[pos+size:pos+size+length]
    return list(struct.unpack(f'>{len(data)//2}H', data))

def unpack_bytes_list(raw: bytes, pos: int, size1: int, size2: int) -> list[int]:
    if size1 > 0:
        length = unpack_int(raw, pos, size1)
    else: # by the end of raw block
        length = len(raw) - pos
    if length == 0:
        return []
    pos += size1
    endpos = pos + length
    content = []
    while pos < endpos:
        data = unpack_bytes(raw, pos, size2)
        content.append(data)
        pos += size2 + len(data)
    return content
