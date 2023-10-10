#!/usr/bin/python3

from abc import ABC, abstractmethod

class AEAD:
    """AEAD abstract class

    Currently only TLS1.3 functionality is implemented
    """
    tls_version: int
    my_nonce: int # int, so calculations are easier with them
    my_rec_seq_num: int
    peer_nonce: int
    peer_rec_seq_num: int
    
    def __init__(self, *, tls_version: str = 0x0304) -> None:
        if tls_version != 0x0304:
            raise NotImplementedError("Selected version is not supported by AEAD")
        self.tls_version = tls_version

    def set_my_key(self, key: bytes) -> None:
        self.my_key = key

    def set_peer_key(self, key: bytes) -> None:
        self.peer_key = key

    def set_my_nonce(self, nonce: bytes) -> None:
        self.my_nonce = int.from_bytes(nonce, 'big')
        self.my_rec_seq_num = 0

    def set_peer_nonce(self, nonce: bytes) -> None:
        self.peer_nonce = int.from_bytes(nonce, 'big')
        self.peer_rec_seq_num = 0

    def encrypt(self, plain_text: bytes, auth_data: bytes) -> (bytes, bytes):
        nonce = (self.my_nonce ^ self.my_rec_seq_num).to_bytes(12, 'big')
        cipher_text, auth_tag = self.encrypt_message(plain_text, auth_data, nonce)
        self.my_rec_seq_num += 1
        return cipher_text, auth_tag

    def decrypt(self, cipher_text: bytes, auth_data: bytes) -> (bytes, bytes):
        nonce = (self.peer_nonce ^ self.peer_rec_seq_num).to_bytes(12, 'big')
        plain_text, auth_tag = self.decrypt_message(cipher_text, auth_data, nonce)
        self.peer_rec_seq_num += 1
        return plain_text, auth_tag
