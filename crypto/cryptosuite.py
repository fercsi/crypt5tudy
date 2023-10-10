#!/usr/bin/python3

from .ciphersuite import *
from .hashfunctionfactory import hash_function_factory
from .aead import AEAD
from .aesgcm import AES_GCM
from .hkdf import HKDF

class CryptoSuite:
    def __init__(self, cipher_suite: int|str|CipherSuite):
        if isinstance(cipher_suite, int):
            self.cipher_suite = CIPHER_SUITE_BY_ID.get(cipher_suite)
        else:
            self.cipher_suite = CIPHER_SUITE_BY_NAME.get(cipher_suite)
        if self.cipher_suite is None:
            raise IndexError(f'Cipher Suite {cipher_suite} is unknown')
        self.setup_cipher_suite()

    def setup_cipher_suite(self):
        self.hash_function = hash_function_factory.create(self.cipher_suite.hash)
        self.hkdf = HKDF(self.hash_function)
        if self.cipher_suite.encryption == 'AES_GCM_13':
            self.aead = AES_GCM()
        else:
            raise NotImplementedError(f'Encryption {self.cipher_suite.encryption} is not implemented')
        self.key_length = self.cipher_suite.k_len
        self.hash_length = self.hash_function(b'').digest_size

    def set_my_key(self, key: bytes) -> None:
        self.aead.set_my_key(key)

    def set_my_nonce(self, nonce: bytes) -> None:
        self.aead.set_my_nonce(nonce)

    def set_peer_key(self, key: bytes) -> None:
        self.aead.set_peer_key(key)

    def set_peer_nonce(self, nonce: bytes) -> None:
        self.aead.set_peer_nonce(nonce)

    def encrypt(self, plain_text: bytes, auth_data: bytes = b'') -> bytes:
        return self.aead.encrypt(plain_text, auth_data)

    def decrypt(self, plain_text: bytes, auth_data: bytes = b'', *, force=False) -> bytes:
        return self.aead.decrypt(plain_text, auth_data)
