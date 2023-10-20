#!/usr/bin/python3

import pytest
from crypto.hash import sha224, sha256, sha384, sha512

# processing 1M data takes too much time, and it is even unnecessary. It is
# still here, because it has been defined in the specifications:
# FIPS 180-2 (sha256, sha384, sha512), RFC3874 (sha224)
TEST_LONG_MESSAGES = False

@pytest.mark.parametrize('message,func,hash', (
    # ==== SHA-224 ====
    (   # empty
        b'',
        sha224,
        'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'),
    (   # short message - RFC3874
        b'abc',
        sha224,
        '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'),
    (   # 55 bytes (single round)
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop',
        sha224,
        '7a027d88e394d289ed7a10a918b93d1f210b4741d44534ce64275ab9'),
    (   # 56 bytes (two rounds) - RFC3874
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        sha224,
        '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525'),
    (   # 63 bytes (closing '1' in first round)
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqr',
        sha224,
        '3420abbd1a99e6a37a6d87540ddbc079ba4c2ea0931aa340c5d39626'),
    (   # 64 bytes (closing '1' in second round)
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqrs',
        sha224,
        '6b24d4a8f3cd9bda5475a604683bfa8607d1650195940f5cc1cf09d9'),
    (   # longer message
        b'a' * 1000,
        sha224,
        '4e8f0ce90b64661a2b5e84be6d93a7d9b76871062f1814433d04a03d'),
    (   # long message - RFC3874
        b'a' * 1_000_000,
        sha224,
        '20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67'),
    # ==== SHA-256 ====
    (   # empty
        b'',
        sha256,
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    (   # short message - FIPS 180-2
        b'abc',
        sha256,
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    (   # 55 bytes (single round)
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop',
        sha256,
        'aa353e009edbaebfc6e494c8d847696896cb8b398e0173a4b5c1b636292d87c7'),
    (   # 56 bytes (two rounds) - FIPS 180-2
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        sha256,
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'),
    (   # 63 bytes (closing '1' in first round)
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqr',
        sha256,
        'dcfbe3dbf9a7b771b3ca284054dae5f836d419a841a5d45eae54fa413dc813b8'),
    (   # 64 bytes (closing '1' in second round)
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqrs',
        sha256,
        '5a5748c5c07341a6c8b2c06ba633247dc04b712d28fd2951cc91160915902d67'),
    (   # longer message
        b'a' * 1000,
        sha256,
        '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3'),
    (   # long message - FIPS 180-2
        b'a' * 1_000_000,
        sha256,
        'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'),
    # ==== SHA-384 ====
    (   # empty
        b'',
        sha384,
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'),
    (   # short message - FIPS 180-2
        b'abc',
        sha384,
        'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'),
    (   # 111 bytes (single round)
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrst',
        sha384,
        '3f019199e040b6fafc102a7f935852885f32bc70f8bf276f8a069ffe143d11493225bbd501d3e652f0c0513e2392920b'),
    (   # 112 bytes (two rounds) - FIPS 180-2
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
        sha384,
        '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039'),
    (   # 127 bytes (closing '1' in first round)
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuopqrstuvpqrstuv',
        sha384,
        'ebf8e452d9e109005aa938e5637d751ca6f4f2301597dcb620986342f1546ac482544761b5cfefe93c63e97b096f64e7'),
    (   # 128 bytes (closing '1' in second round)
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuopqrstuvpqrstuvw',
        sha384,
        '37ecb6abff1fe994857d90a363a4c61282b1c26f263859042a0b3755efa287633ce5029ca0d5186616fdb748d97b305d'),
    (   # longer message
        b'a' * 1000,
        sha384,
        'f54480689c6b0b11d0303285d9a81b21a93bca6ba5a1b4472765dca4da45ee328082d469c650cd3b61b16d3266ab8ced'),
    (   # long message - FIPS 180-2
        b'a' * 1_000_000,
        sha384,
        '9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985'),
    # ==== SHA-512 ====
    (   # empty
        b'',
        sha512,
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'),
    (   # short message - FIPS 180-2
        b'abc',
        sha512,
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'),
    (   # 111 bytes (single round)
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrst',
        sha512,
        '0988db6ee79aa0b4b28b0b3d2d9d50a0c2782144ba51a0405bdf82f04e895fb6a4848953a0028d33dd6fce20c3994d078f8382dfc48903521c7aa744ddebf6c6'),
    (   # 112 bytes (two rounds) - FIPS 180-2
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
        sha512,
        '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'),
    (   # 127 bytes (closing '1' in first round)
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuopqrstuvpqrstuv',
        sha512,
        'c64ab1a914c3221c14dfb08be32b38491ddcfaacb16b0a804b43094da70d20284a1dc931d3362ae891de99cffb621d86c05761927f7cf94a564a4a61c738100b'),
    (   # 128 bytes (closing '1' in second round)
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuopqrstuvpqrstuvw',
        sha512,
        '8cbb7d3645d5e421ad7eb6c7afe357391f72666451f6a6bfb435407d596d3a5ed26e1194675f6c0fd56a15c7f1d904d11af3d046d315864c2377b505912d4c4f'),
    (   # longer message
        b'a' * 1000,
        sha512,
        '67ba5535a46e3f86dbfbed8cbbaf0125c76ed549ff8b0b9e03e0c88cf90fa634fa7b12b47d77b694de488ace8d9a65967dc96df599727d3292a8d9d447709c97'),
    (   # long message - FIPS 180-2
        b'a' * 1_000_000,
        sha512,
        'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b'),
))
def test_sha(message, func, hash):
    if not TEST_LONG_MESSAGES and len(message) >= 1_000_000:
        return
    o = func(message)
    assert o.hexdigest() == hash
    assert o.digest().hex() == hash
    assert len(o.digest()) == o.digest_size
    o = func()
    o.update(message)
    assert o.hexdigest() == hash

# TODO Separate tests
# TODO test name
# TODO test update after digesting
