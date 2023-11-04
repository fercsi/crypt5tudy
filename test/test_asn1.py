#!/usr/bin/python3

import pytest
from util.asn1 import *

# DON'T FORGET: other classes, construction, encapsulation, unique methods(e.g. getitem...)
@pytest.mark.parametrize('ber,annotation,printout', (
    # ==== EOC, TYPE 0 ====
    (   '00 00',
        None,
        '[EOC]: ~'   ),
    (   '00 00',
        ('Name',),
        'Name[EOC]: ~'   ),
    # ==== BOOLEAN, TYPE 1 ====
    (   '01 01 00',
        None,
        '[BOOLEAN]: false'   ),
    (   '01 01 ff',
        ('Name',),
        'Name[BOOLEAN]: true'   ),
    # ==== INTEGER, TYPE 2 ====
    # NOTE: common data representation is tested only here
    (   '02 01 00',
        None,
        '[INTEGER]: 0'   ),
    (   '02 02 01 02',
        ('Name',),
        'Name[INTEGER]: 258'   ),
    (   '02 81 81 01' + '00' * 128,
        (None, 'dec'),
        '[INTEGER]: ' + str(1<<1024)   ),
    (   '02 82 0101 01' + '00' * 256,
        None,
        '[INTEGER]: ' + str(1<<2048)   ),
    (   '02 04 cafebeaf',
        (None, 'hex'),
        '[INTEGER]: cafebeaf'   ),
    (   '02 04 cafebeaf',
        (None, 'bin'),
        '[INTEGER]: 11001010111111101011111010101111'   ),
    (   '02 01 00',
        (None, 'hex_block'),
        '[INTEGER]:\n  00'   ),
    (   '02 10' + 'b6' * 16,
        (None, 'hex_block'),
        '[INTEGER]:\n ' + ' b6' * 16   ),
    (   '02 11' + 'b6' * 17,
        (None, 'hex_block'),
        '[INTEGER]:\n ' + ' b6' * 16 + '\n  b6'   ),
    (   '02 01 00',
        (None, 'bin_block'),
        '[INTEGER]:\n  00000000'   ),
    (   '02 04' + 'b6' * 4,
        (None, 'bin_block'),
        '[INTEGER]:\n ' + ' 10110110' * 4   ),
    (   '02 05' + 'b6' * 5,
        (None, 'bin_block'),
        '[INTEGER]:\n ' + ' 10110110' * 4 + '\n  10110110'   ),
    # ==== BIT STRING, TYPE 3 ====
    # NOTE: data representetion 'dec' is tested here
    (   '03 01 00',
        None,
        '[BIT STRING]: ~'   ),
    (   '03 02 07 80', # data formatting is tested detailef with INTEGER
        ('Name',),
        ( 'Name[BIT STRING]:',
          '  80' )   ),
    (   '03 03 00 0102',
        ('Name','dec'),
        'Name[BIT STRING]: 258'   ),
    (   '03 02 00 80',
        (None,'bin'),
        '[BIT STRING]: 10000000'   ),
    (   '03 02 01 80',
        (None,'bin'),
        '[BIT STRING]: 1000000-'   ),
    (   '03 02 07 80',
        (None,'bin'),
        '[BIT STRING]: 1-------'   ),
    (   '03 02 05 80',
        (None,'bin_block'),
        ( '[BIT STRING]:',
          '  100-----' )   ),
    (   '03 05 05' + 'b6' * 4,
        (None,'bin_block'),
        ( '[BIT STRING]:',
          '  10110110 10110110 10110110 101-----' )   ),
    (   '03 06 05' + 'b6' * 5,
        (None,'bin_block'),
        ( '[BIT STRING]:',
          '  10110110 10110110 10110110 10110110',
          '  101-----' )   ),
    (   '23 00',
        None,
        '*[BIT STRING]: ~'   ),
    (   '23 0e   03 01 00   03 02 04 50   03 05 00 cafe beef',
        (None, [(None,), (None, 'bin')]),
        ( '*[BIT STRING]:',
          '  [BIT STRING]: ~',
          '  [BIT STRING]: 0101----',
          '  [BIT STRING]:',
          '    ca fe be ef' )   ),
    # ==== OCTET STRING, TYPE 4 ====
    (   '04 00',
        None,
        '[OCTET STRING]: ~'   ),
    (   '04 01 b6',
        ('Name',),
        ( 'Name[OCTET STRING]:',
          '  b6' )   ),
    (   '24 00',
        None,
        '*[OCTET STRING]: ~'   ),
    (   '24 0d   04 00   04 02 04 50   04 05 00 cafe beef',
        (None, [(None,), (None, 'hex')]),
        ( '*[OCTET STRING]:',
          '  [OCTET STRING]: ~',
          '  [OCTET STRING]: 0450',
          '  [OCTET STRING]:',
          '    00 ca fe be ef' )   ),
    # ==== NULL, TYPE 5 ====
    (   '05 00',
        None,
        '[NULL]: ~'   ),
    (   '05 00',
        ('Name',),
        'Name[NULL]: ~'   ),
    # ==== OBJECT IDENTIFIER, TYPE 6 ====
    # NOTE: First level OID cannot be used, since 0.0, 1.0... is in use
    (   '06 01 00',
        None,
        '[OBJECT IDENTIFIER]: 0.0'   ),
    (   '06 01 2a',
        None,
        '[OBJECT IDENTIFIER]: 1.2'   ),
    (   '06 03 2a 86 48',
        None,
        '[OBJECT IDENTIFIER]: 1.2.840'   ),
    (   '06 06 2a 86 48 86 f7 0d',
        None,
        '[OBJECT IDENTIFIER]: 1.2.840.113549 (rsadsi)'   ),
    (   '06 09 2a 86 48 86 f7 0d 01 01 01',
        None,
        '[OBJECT IDENTIFIER]: 1.2.840.113549.1.1.1 (rsaEncryption)'   ),
    # ==== EXTERNAL, TYPE 8 ====
    (   '28 00',
        None,
        '*[EXTERNAL]: ~'   ),
    (   '28 09   04 00   02 02 03 e8   01 01 ff',
        (None, [(None,), ('Name',)]),
        ( '*[EXTERNAL]:',
          '  [OCTET STRING]: ~',
          '  Name[INTEGER]: 1000',
          '  [BOOLEAN]: true' )   ),
    # ==== UTF8 STRING, TYPE 12 ====
    (   '0c 00',
        None,
        '[UTF8 STRING]: \'\''   ),
    (   '0c 04 41 42 43 44',
        None,
        '[UTF8 STRING]: \'ABCD\''   ),
    (   '0c 05 72 c2 b2 cf 80',
        None,
        '[UTF8 STRING]: \'r²π\''   ),
    (   '0c 03 e2 98 ba',
        None,
        '[UTF8 STRING]: \'☺\''   ),
    (   '0c 05 72 c2 b2 cf 80',
        (None, 'hex_block'),
        ( '[UTF8 STRING]:',
          '  72 c2 b2 cf 80' )   ),
    (   '2c 00',
        None,
        '*[UTF8 STRING]: ~'   ),
    (   '2c 0e   0c 00   0c 03 68 65 78   0c 05 41 53 4e 2e 31',
        (None, [(None,), (None, 'hex')]),
        ( '*[UTF8 STRING]:',
          '  [UTF8 STRING]: \'\'',
          '  [UTF8 STRING]: 686578',
          '  [UTF8 STRING]: \'ASN.1\'' )   ),
    # ==== SEQUENCE, TYPE 16 ====
    (   '30 00',
        None,
        '*[SEQUENCE]: ~'   ),
    (   '30 09   04 00   02 02 03 e8   01 01 ff',
        (None, [(None,), ('Name',)]),
        ( '*[SEQUENCE]:',
          '  [OCTET STRING]: ~',
          '  Name[INTEGER]: 1000',
          '  [BOOLEAN]: true' )   ),
    (   '30 0b   04 00   30 07   02 02 03 e8   01 01 ff',
        (None, [(None,), ('Name',[('Sub',)])]),
        ( '*[SEQUENCE]:',
          '  [OCTET STRING]: ~',
          '  *Name[SEQUENCE]:',
          '    Sub[INTEGER]: 1000',
          '    [BOOLEAN]: true' )   ),
    # ==== SET, TYPE 17 ====
    (   '31 00',
        None,
        '*[SET]: ~'   ),
    (   '31 11    30 06 01 01 00 02 01 2a   30 07 01 01 ff 02 02 cafe',
        (None, [None, ('Name',[None, (None, 'hex')])]),
        ( '*[SET]:',
          '  *[SEQUENCE]:',
          '    [BOOLEAN]: false',
          '    [INTEGER]: 42',
          '  *Name[SEQUENCE]:',
          '    [BOOLEAN]: true',
          '    [INTEGER]: cafe' )   ),
    # ==== PRINTABLE STRING, TYPE 19 ====
    (   '13 00',
        None,
        '[PRINTABLE STRING]: \'\''   ),
    (   '13 04 41 42 43 44',
        None,
        '[PRINTABLE STRING]: \'ABCD\''   ),
    (   '13 05 72 c2 b2 cf 80', # No error message, but conversion fails
        None,
        '[PRINTABLE STRING]: \'r����\''   ),
    (   '13 03 e2 98 ba',
        None,
        '[PRINTABLE STRING]: \'���\''   ),
    (   '13 05 72 c2 b2 cf 80',
        (None, 'hex_block'),
        ( '[PRINTABLE STRING]:',
          '  72 c2 b2 cf 80' )   ),
    (   '33 00',
        None,
        '*[PRINTABLE STRING]: ~'   ),
    (   '33 0e   13 00   13 03 68 65 78   13 05 41 53 4e 2e 31',
        (None, [(None,), (None, 'hex')]),
        ( '*[PRINTABLE STRING]:',
          '  [PRINTABLE STRING]: \'\'',
          '  [PRINTABLE STRING]: 686578',
          '  [PRINTABLE STRING]: \'ASN.1\'' )   ),
    # ==== UTC TIME, TYPE 23 ====
    (   '17 0c 3233 3131 3033 3230 3132 3239',
        None,
        '[UTC TIME]: 2023-11-03 20:12:29'   ),
))
def test_deserialize(ber, annotation, printout):
    ber_raw = bytes.fromhex(ber)
    asn1_object, length = Asn1._from_ber(ber_raw, 0)
    if annotation:
        asn1_object.annotate(*annotation)
    if isinstance(printout, tuple):
        printout = '\n'.join(printout)
    assert str(asn1_object) == printout
    # check if deserialization used exactly the amount of bytes as expected:
    assert len(ber_raw) == length


# ==== EOC, TYPE 0 ====
def test_create_eoc():
    obj = Asn1Eoc()
    assert Asn1.to_ber(obj).hex() == '0000'


# ==== BOOLEAN, TYPE 1 ====
@pytest.mark.parametrize('value, result', (
    (False, '010100'),
    (True, '0101ff'),
))
def test_create_boolean(value, result):
    obj = Asn1Boolean(value)
    assert Asn1.to_ber(obj).hex() == result
    obj = Asn1Boolean()
    obj.value = value
    assert Asn1.to_ber(obj).hex() == result
    assert bool(obj) == value


# ==== INTEGER, TYPE 2 ====
@pytest.mark.parametrize('value, result', (
    (0, '020100'),
    (182, '0201b6'),
    (258, '02020102'),
    (1<<1008, '027f01' + '00'*126),
    (1<<1016, '02818001' + '00'*127),
    (1<<2040, '0282010001' + '00'*255),
))
def test_create_integer(value, result):
    obj = Asn1Integer(value)
    assert Asn1.to_ber(obj).hex() == result
    obj = Asn1Integer()
    obj.value = value
    assert Asn1.to_ber(obj).hex() == result
    assert int(obj) == value


# ==== BIT STRING, TYPE 3 ====
# TODO: __getitem__, bytes(), length property
@pytest.mark.parametrize('bits, result', (
    ( tuple(), '030100' ),
    ( (0,), '03020780' ),
    ( (4,), '03020308' ),
    ( (7,), '03020001' ),
    ( (2,4,5), '0302022c' ),
    ( (8,), '0303070080' ),
    ( (3,7,11), '0303041110' ),
))
def test_create_bitstring(bits, result):
    obj = Asn1BitString(bits)
    assert Asn1.to_ber(obj).hex() == result
    obj = Asn1BitString()
    for i in bits:
        obj[i] = 1
    assert Asn1.to_ber(obj).hex() == result

@pytest.mark.parametrize('bits, result', (
    ( {(2,6,1): 0b1101}, '03020234' ),
    ( {(5,13,1): 0b1100_1010}, '0303030650' ),
    ( {(5,13,None): 0b1100_1010}, '0303030650' ),
    ( {13:1, (5,13,None): 0b1100_1010}, '0303020654' ),
    ( {13:1, (None,None,None): 0b1100_1010}, '0303020328' ),
    ( {13:1, (5,None,None): 0b1100_1010}, '0303020328' ),
    ( {13:1, (-9,None,None): 0b1100_1010}, '0303020328' ),
    ( {13:1, (None,6,None): 0b1100_1010}, '0303022804' ),
    ( {13:1, (None,-8,None): 0b1100_1010}, '0303022804' ),
    ( {13:1, (None,None,2): 0b1100_1010}, '0303028224' ),
    ( {13:1, (None,None,-1): 0b1100_1010}, '0303025300' ),
    ( {13:1, (None,None,-2): 0b1100_1010}, '0303021104' ),
))
def test_create_bitstring_slice(bits, result):
    obj = Asn1BitString()
    for ndx, value in bits.items():
        obj[ndx if isinstance(ndx, int) else slice(*ndx)] = value
    assert Asn1.to_ber(obj).hex() == result

def test_create_bitstring_constructed():
    obj = Asn1BitString(constructed = True)
    assert Asn1.to_ber(obj) == bytes.fromhex('23 00')
    obj.append(Asn1BitString([3,8,14]))
    obj.append(Asn1BitString())
    assert Asn1.to_ber(obj) == bytes.fromhex('23 08'
            + '03 03 01 1082'
            + '03 01 00')


# ==== OCTET STRING, TYPE 4 ====
# TODO: data=, bytes, getitem, length property
@pytest.mark.parametrize('octets, result', (
    ( {}, '0400' ),
    ( {0: 0xb6}, '0401b6' ),
    ( {2: 0xb6}, '04030000b6' ),
    ( {4: 0xb6, 2: b'\x89'}, '040500008900b6' ),
    ( {(2,5,1): 0xb6}, '04050000b6b6b6' ),
    ( {(2,5,1): b'\x42\x89\xb6'}, '040500004289b6' ),
    ( {(2,5,1): 0xb6, (1,3,1): 0x2a}, '0405002a2ab6b6' ),
    ( {8:0xb6, (5,None,None): b'ABCDEF'}, '040b0000000000414243444546' ),
    ( {8:0xb6, (-4,None,None): b'ABCDEF'}, '040b0000000000414243444546' ),
    ( {8:0xb6, (None,5,None): b'ABCDEF'}, '04094142434445000000b6' ),
    ( {8:0xb6, (None,-4,None): b'ABCDEF'}, '04094142434445000000b6' ),
    ( {8:0xb6, (None,None,2): b'ABCDEF'}, '040b4100420043004400450046' ),
    ( {8:0xb6, (None,None,-1): b'ABCDEF'}, '0409000000464544434241' ),
    ( {8:0xb6, (None,None,-2): b'ABCDEF'}, '0409450044004300420041' ),
    ( {8:0xb6, (6,1,-2): b'ABCDEF'}, '04090000430042004100b6' ),
))
def test_create_octetstring_slice(octets, result):
    obj = Asn1OctetString()
    for ndx, value in octets.items():
        obj[ndx if isinstance(ndx, int) else slice(*ndx)] = value
    assert Asn1.to_ber(obj).hex() == result

def test_create_octetstring_constructed():
    obj = Asn1OctetString(constructed = True)
    assert Asn1.to_ber(obj) == bytes.fromhex('24 00')
    obj.append(Asn1OctetString(bytes([42])))
    obj.append(Asn1OctetString())
    assert Asn1.to_ber(obj) == bytes.fromhex('24 05'
            + '04 01 2a'
            + '04 00')


# ==== NULL, TYPE 5 ====
def test_create_null():
    obj = Asn1Null()
    assert Asn1.to_ber(obj).hex() == '0500'


# ==== OBJECT IDENTIFIER, TYPE 6 ====
@pytest.mark.parametrize('oid, result', (
    ( [0,0], '06 01 00' ),
    ( [1,0], '06 01 28' ),
    ( [1,2], '06 01 2a' ),
    ( [1,2,840], '06 03 2a 86 48' ),
    ( (1,2,840,113549), '06 06 2a 86 48 86 f7 0d' ),
    ( '1.2.840.113549.1.1.1', '06 09 2a 86 48 86 f7 0d 01 01 01' ),
))
def test_create_objectidentifier(oid, result):
    result = bytes.fromhex(result)
    obj = Asn1ObjectIdentifier(oid)
    assert Asn1.to_ber(obj) == result
    obj = Asn1ObjectIdentifier()
    obj.arcs = oid
    assert Asn1.to_ber(obj) == result


# ==== EXTERNAL, TYPE 8 ====
def test_create_external():
    obj = Asn1External()
    assert Asn1.to_ber(obj) == bytes.fromhex('28 00')
    obj.append(Asn1Boolean(True))
    obj.append(Asn1Integer(42))
    obj.append(Asn1OctetString())
    assert Asn1.to_ber(obj) == bytes.fromhex('28 08'
            + '01 01 ff'
            + '02 01 2a'
            + '04 00')


# ==== UTF8 STRING, TYPE 12 ====
@pytest.mark.parametrize('text, result', (
    ( '', '0c 00' ),
    ( 'ABCD', '0c 04 41 42 43 44' ),
    ( 'r²π', '0c 05 72 c2 b2 cf 80' ),
    ( '☺', '0c 03 e2 98 ba' ),
))
def test_create_utf8string(text, result):
    result = bytes.fromhex(result)
    obj = Asn1Utf8String(text)
    assert Asn1.to_ber(obj) == result
    obj = Asn1Utf8String()
    obj.text = text
    assert Asn1.to_ber(obj) == result

def test_create_utf8string_constructed():
    obj = Asn1Utf8String(constructed = True)
    assert Asn1.to_ber(obj) == bytes.fromhex('2c 00')
    obj.append(Asn1Utf8String('ABCD'))
    obj.append(Asn1Utf8String())
    assert Asn1.to_ber(obj) == bytes.fromhex('2c 08'
            + '0c 04 41 42 43 44'
            + '0c 00')


# ==== SEQUENCE, TYPE 16 ====
def test_create_sequence():
    obj = Asn1Sequence()
    assert Asn1.to_ber(obj) == bytes.fromhex('30 00')
    obj.append(Asn1Boolean(True))
    obj.append(Asn1Integer(42))
    obj.append(Asn1OctetString())
    assert Asn1.to_ber(obj) == bytes.fromhex('30 08'
            + '01 01 ff'
            + '02 01 2a'
            + '04 00')


# ==== SET, TYPE 17 ====
def test_create_set():
    obj = Asn1Set()
    assert Asn1.to_ber(obj) == bytes.fromhex('31 00')
    seq = Asn1Sequence()
    seq.append(Asn1Boolean(True))
    seq.append(Asn1Integer(42))
    obj.append(seq)
    seq = Asn1Sequence()
    seq.append(Asn1Boolean(False))
    seq.append(Asn1Integer(258))
    obj.append(seq)
    assert Asn1.to_ber(obj) == bytes.fromhex('31 11'
            + '30 06'
                + '01 01 ff'
                + '02 01 2a'
            + '30 07'
                + '01 01 00'
                + '02 02 01 02')
