#!/usr/bin/python3

import pytest
from crypto.hash import sha256

@pytest.mark.parametrize('message,func,hash', (
    # ==== SHA256 ====
    (   b'',
        sha256,
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    (   b'abc',
        sha256,
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    (   b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop',
        sha256,
        'aa353e009edbaebfc6e494c8d847696896cb8b398e0173a4b5c1b636292d87c7'),
    (   b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        sha256,
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'),
    (   b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqo',
        sha256,
        '2c4cc4c7e3a19f0c58258b551d3a4af984873cb55cc53b93dd8facf3c1ba935a'),
    (   b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqr',
        sha256,
        'dcfbe3dbf9a7b771b3ca284054dae5f836d419a841a5d45eae54fa413dc813b8'),
    (   b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqrs',
        sha256,
        '5a5748c5c07341a6c8b2c06ba633247dc04b712d28fd2951cc91160915902d67'),
    (   b'a' * 1_000_000,
        sha256,
        'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'),
))
def test_sha(message, func, hash):
    o = func(message)
    assert o.hexdigest() == hash
