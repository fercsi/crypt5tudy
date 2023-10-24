#!/usr/bin/python3

from .aead import AEAD
from .cipher.aes import aes
from .gcm import GCM

class AES_GCM(AEAD):
    def encrypt_message(self, plain_text: bytes, auth_data: bytes, nonce: bytes) -> (bytes, bytes):
        gcm = GCM(aes(self.my_key))
        return gcm.encrypt(plain_text, auth_data, nonce)

    def decrypt_message(self, cipher_text: bytes, auth_data: bytes, nonce: bytes) -> (bytes, bytes):
        gcm = GCM(aes(self.peer_key))
        return gcm.decrypt(cipher_text, auth_data, nonce)
