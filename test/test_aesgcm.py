#!/usr/bin/python3

import pytest
from crypto.cipher.aes import aes as AES
from crypto import GCM

# David A. McGrew, John Viega: The Galois/Counter Mode of Operation (GCM)
# Appendix B, AES Test Vectors
# Note: Currently only IV-s length of 96 bits are supported
TEST_VECTORS = ('key,plain_text,auth_data,iv,cipher_text,auth_tag', (
    # ==== AES 128 ====
    (   '00000000000000000000000000000000', #1
        '',
        '',
        '000000000000000000000000',
        '',
        '58e2fccefa7e3061367f1d57a4e7455a'   ),
    (   '00000000000000000000000000000000', #2
        '00000000000000000000000000000000',
        '',
        '000000000000000000000000',
        '0388dace60b6a392f328c2b971b2fe78',
        'ab6e47d42cec13bdf53a67b21257bddf'   ),
    (   'feffe9928665731c6d6a8f9467308308', #3
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        '',
        'cafebabefacedbaddecaf888',
        '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
        '4d5c2af327cd64a62cf35abd2ba6fab4'   ),
    (   'feffe9928665731c6d6a8f9467308308', #4 
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'cafebabefacedbaddecaf888',
        '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
        '5bc94fbc3221a5db94fae95ae7121a47'   ),
    (   'feffe9928665731c6d6a8f9467308308', #5
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'cafebabefacedbad',
        '61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598',
        '3612d2e79e3b0785561be14aaca2fccb'   ),
    (   'feffe9928665731c6d6a8f9467308308', #6
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
        '8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5',
        '619cc5aefffe0bfa462af43c1699d050'   ),
    # ==== AES 192 ====
    (   '000000000000000000000000000000000000000000000000', #7
        '',
        '',
        '000000000000000000000000',
        '',
        'cd33b28ac773f74ba00ed1f312572435'   ),
    (   '000000000000000000000000000000000000000000000000', #8
        '00000000000000000000000000000000',
        '',
        '000000000000000000000000',
        '98e7247c07f0fe411c267e4384b0f600',
        '2ff58d80033927ab8ef4d4587514f0fb'   ),
    (   'feffe9928665731c6d6a8f9467308308feffe9928665731c', #9
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        '',
        'cafebabefacedbaddecaf888',
        '3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256',
        '9924a7c8587336bfb118024db8674a14'   ),
    (   'feffe9928665731c6d6a8f9467308308feffe9928665731c', #10
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'cafebabefacedbaddecaf888',
        '3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710',
        '2519498e80f1478f37ba55bd6d27618c'   ),
    (   'feffe9928665731c6d6a8f9467308308feffe9928665731c', #11
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'cafebabefacedbad',
        '0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7',
        '65dcc57fcf623a24094fcca40d3533f8'   ),
    (   'feffe9928665731c6d6a8f9467308308feffe9928665731c', #12
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
        'd27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b',
        'dcf566ff291c25bbb8568fc3d376a6d9'   ),
    # ==== AES 256 ====
    (   '0000000000000000000000000000000000000000000000000000000000000000', #13
        '',
        '',
        '000000000000000000000000',
        '',
        '530f8afbc74536b9a963b4f1c4cb738b'   ),
    (   '0000000000000000000000000000000000000000000000000000000000000000', #14
        '00000000000000000000000000000000',
        '',
        '000000000000000000000000',
        'cea7403d4d606b6e074ec5d3baf39d18',
        'd0d1c8a799996bf0265b98b5d48ab919'   ),
    (   'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', #15
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        '',
        'cafebabefacedbaddecaf888',
        '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
        'b094dac5d93471bdec1a502270e3cc6c'   ),
    (   'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', #16
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'cafebabefacedbaddecaf888',
        '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
        '76fc6ece0f4e1768cddf8853bb2d551b'   ),
    (   'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', #17
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'cafebabefacedbad',
        'c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f',
        '3a337dbf46a792c45e454913fe2ea8f2'   ),
    (   'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', #18
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
        '5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f',
        'a44a8266ee1c8eb0c8b5d4cf5ae9f19a'   ),
))

@pytest.mark.parametrize(*TEST_VECTORS)
def test_encryption(key,plain_text,auth_data,iv,cipher_text,auth_tag):
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    plain_text = bytes.fromhex(plain_text)
    auth_data = bytes.fromhex(auth_data)
    cipher_text = bytes.fromhex(cipher_text)
    auth_tag = bytes.fromhex(auth_tag)

    aes = AES(key)
    enc = GCM(aes)
    chk_cipher_text, chk_auth_tag = enc.encrypt(plain_text, auth_data, iv)
    assert chk_cipher_text == cipher_text
    assert chk_auth_tag == auth_tag

@pytest.mark.parametrize(*TEST_VECTORS)
def test_decryption(key,plain_text,auth_data,iv,cipher_text,auth_tag):
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    plain_text = bytes.fromhex(plain_text)
    auth_data = bytes.fromhex(auth_data)
    cipher_text = bytes.fromhex(cipher_text)
    auth_tag = bytes.fromhex(auth_tag)

    aes = AES(key)
    enc = GCM(aes)
    chk_plain_text, chk_auth_tag = enc.decrypt(cipher_text, auth_data, iv)
    assert chk_plain_text == plain_text
    assert chk_auth_tag == auth_tag
