#!/usr/bin/python3
"""Serialization utility module

This module contains Common functions to serialize and deserialize simple
constructs. This type of interpretation us used overall in network
communication.

Numeric values
==============

Numeric data is always stored in network byte order (big endian). Signed values
are represented in *2's complement*.

Strings and lists
=================

Strings (character and byte) and lists have variable length, so there is an
additional length field in front of the raw content.

+--------+------------------+
| length | Content...       |
+--------+------------------+

``length`` contains the length of the content in **bytes**. Size (``lensize``)
of ``length`` field depends on the maximum content length. If the content is
always shorter than 256, ``lensize`` is 1, if it is shorter than 65536, then it
is 2, etc.

Examples
--------

>>> util.pack_str("Hello World! 😀", 2)
b'\x00\x11Hello World! \xf0\x9f\x98\x80'
>>> util.pack_u16_list([42, 258], 1)
b'\x04\x00*\x01\x02'
"""

import struct

# Pack constructs

def pack_uint(value: int, size: int|None = None) -> bytes:
    """Pack unsigned integer

    Parameters
    ----------
    value : int
        Value to be serialized
    size : int, optional
        Number of bytes to store value in. If not given, length of the
        serialized buffer is the shortest posdible.

    Returns
    -------
    bytes
        Serialized buffer
    """
    if size is None:
        size = value.bit_length() + 7 >> 3 or 1
    return value.to_bytes(size, 'big')

def pack_sint(value: int, size: int|None = None) -> bytes:
    """Pack signed integer

    Parameters
    ----------
    value : int
        Value to be serialized
    size : int, optional
        Number of bytes to store value in. If not given, length of the
        serialized buffer is the shortest posdible. The signed value is
        represented in *2's complement*, so MSB is always the sign bit. This
        means, converting `+128` results in two bytes: `bytes('\x00\x80')`

    Returns
    -------
    bytes
        Serialized buffer
    """
    if size is None:
        c = value if value >= 0 else value + 1
        size = (c.bit_length() >> 3) + 1
    return value.to_bytes(size, 'big', signed=True)

def pack_u8(value: int) -> bytes:
    """Pack unsigned 8 bit integer

    Parameters
    ----------
    value : int
        Value to be serialized

    Returns
    -------
    bytes
        Serialized buffer
    """
    return bytes([value])

def pack_u16(value: int) -> bytes:
    """Pack unsigned 16 bit integer

    Parameters
    ----------
    value : int
        Value to be serialized

    Returns
    -------
    bytes
        Serialized buffer
    """
    return value.to_bytes(2, 'big')

def pack_u24(value: int) -> bytes:
    """Pack unsigned 24 bit integer

    Parameters
    ----------
    value : int
        Value to be serialized

    Returns
    -------
    bytes
        Serialized buffer
    """
    return value.to_bytes(3, 'big')

def pack_u32(value: int) -> bytes:
    """Pack unsigned 32 bit integer

    Parameters
    ----------
    value : int
        Value to be serialized

    Returns
    -------
    bytes
        Serialized buffer
    """
    return value.to_bytes(4, 'big')

def pack_str(char_string: str, lensize: int) -> bytes:
    """Pack character string

    Strings are packed with a ``length`` field followed by the the string
    itself encoded in *utf-8* format. Parameter ``lensize`` determines the
    lensize of the ``length`` field (typically 1 or 2 bytes). Thus, if lensize
    is 1, maximum length of the the **encoded** string is 255.

    Parameters
    ----------
    char_string : str
        Character string to be serialized
    lensize:
        Size of length field

    Returns
    -------
    bytes
        Serialized buffer
    """
    data = char_string.encode()
    return pack_uint(len(data), lensize) + data

def pack_bytes(byte_string: bytes, lensize: int) -> bytes:
    """Pack byte string

    Byte strings are packed with a ``length`` field followed by the the bytes
    themselves. Parameter ``lensize`` determines the size of the ``length``
    field (typically 1 or 2 bytes). Thus, if ``lensize`` is 1, maximum length
    of the string is 255.

    Parameters
    ----------
    byte_string : bytes
        Byte string to be serialized
    lensize:
        Size of length field

    Returns
    -------
    bytes
        Serialized buffer
    """
    data = byte_string
    return pack_uint(len(data), lensize) + data

def pack_u8_list(content: list[int], lensize: int) -> bytes:
    """Pack list of 8 bit unsigned integers

    For information how lists are stored, see "Strings and lists" above.

    Parameters
    ----------
    content : list[int]
        Integer list to be serialized
    lensize:
        Size of length field

    Returns
    -------
    bytes:
        Serialized buffer
    """
    if content:
        data = bytes(content)
    else:
        data = b''
    return pack_uint(len(data), lensize) + data

def pack_u16_list(content: list[int], lensize: int) -> bytes:
    """Pack list of 16 bit unsigned integers

    For information how lists are stored, see "Strings and lists" above.

    Parameters
    ----------
    content : list[int]
        Integer list to be serialized
    lensize:
        Size of length field

    Returns
    -------
    bytes:
        Serialized buffer
    """
    if content:
        data = struct.pack(f'>{len(content)}H', *content)
    else:
        data = b''
    return pack_uint(len(data), lensize) + data

def pack_bytes_list(content: list[bytes], lensize: int) -> bytes:
    """Pack list of byte strings

    Byte strings have arbitrary length and they are simply concatenated. So
    this function assumes, that the byte strings are already packed structs
    with known or determinable size. For more information, see "Strings and
    lists" above.

    Parameters
    ----------
    content : list[bytes]
        List of byte strings to be serialized
    lensize:
        Size of length field

    Returns
    -------
    bytes:
        Serialized buffer
    """
    data = b''.join(content)
    return pack_uint(len(data), lensize) + data

# Unpack constructs

def unpack_uint(raw: bytes, pos: int = 0, size: int|None = None) -> int:
    if size is None:
        return int.from_bytes(raw[pos:], 'big')
    else:
        return int.from_bytes(raw[pos:pos+size], 'big')

def unpack_sint(raw: bytes, pos: int = 0, size: int|None = None) -> int:
    if size is None:
        return int.from_bytes(raw[pos:], 'big', signed=True)
    else:
        return int.from_bytes(raw[pos:pos+size], 'big', signed=True)

def unpack_u8(raw: bytes, pos: int = 0) -> int:
    return int(raw[pos])

def unpack_u16(raw: bytes, pos: int = 0) -> int:
    return int.from_bytes(raw[pos:pos+2], 'big')

def unpack_u24(raw: bytes, pos: int = 0) -> int:
    return int.from_bytes(raw[pos:pos+3], 'big')

def unpack_u32(raw: bytes, pos: int = 0) -> int:
    return int.from_bytes(raw[pos:pos+4], 'big')

def unpack_str(raw: bytes, pos: int, size: int) -> str:
    length = unpack_uint(raw, pos, size)
    data = raw[pos+size:pos+size+length]
    return data.decode()

def unpack_bytes(raw: bytes, pos: int, size: int) -> bytes:
    length = unpack_uint(raw, pos, size)
    data = raw[pos+size:pos+size+length]
    return data

def unpack_u8_list(raw: bytes, pos: int, size: int) -> list[int]:
    length = unpack_uint(raw, pos, size)
    if length == 0:
        return []
    data = raw[pos+size:pos+size+length]
    return list(data)

def unpack_u16_list(raw: bytes, pos: int, size: int) -> list[int]:
    length = unpack_uint(raw, pos, size)
    if length == 0:
        return []
    data = raw[pos+size:pos+size+length]
    return list(struct.unpack(f'>{len(data)//2}H', data))

def unpack_bytes_list(raw: bytes, pos: int, size1: int, size2: int) -> list[int]:
    if size1 > 0:
        length = unpack_uint(raw, pos, size1)
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
