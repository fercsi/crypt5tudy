#!/usr/bin/python3

from crypto.cryptosuite import CryptoSuite

class KeyExchange():
    def __init__(self, crypto_suite: CryptoSuite):
        self.crypto_suite = crypto_suite

    def generate_handshake_keys(self, shared_secret: bytes, messages: list[bytes]) -> None:
        """Generates handshake traffic keys

        Parameters
        ----------
        messages : list of bytes
            `client_hello` and `server_hello` messages (without 5 byte record
            headers)
        """
        hkdf = self.crypto_suite.hkdf
        key_length = self.crypto_suite.key_length

        early_secret = hkdf.extract(None, None)
     
        derived_secret = hkdf.derive_secret(early_secret, "derived", [])
        self.handshake_secret = hkdf.extract(derived_secret, shared_secret)
     
#>        raw_messages = b''.join(messages)
        self.client_handshake_traffic_secret \
            = hkdf.derive_secret(self.handshake_secret, "c hs traffic", messages)
        self.server_handshake_traffic_secret \
            = hkdf.derive_secret(self.handshake_secret, "s hs traffic", messages)
     
        derived_secret = hkdf.derive_secret(self.handshake_secret, "derived", [])
        master_secret = hkdf.extract(derived_secret, None)
     
        self.update_encryption_info(
            self.client_handshake_traffic_secret,
            self.server_handshake_traffic_secret,
            )

    def generate_application_keys(self, messages: list[bytes]) -> None:
        """Generates application traffic keys

        Parameters
        ----------
        messages : list of bytes
            All handshake messages between and including `client_hello` and
            `server_finished` (without 5 byte record headers)
        """
        hkdf = self.crypto_suite.hkdf
        key_length = self.crypto_suite.key_length

        derived_secret = hkdf.derive_secret(self.handshake_secret, "derived", [])
        master_secret = hkdf.extract(derived_secret, None)
     
#>        raw_messages = b''.join(messages)
        self.client_application_traffic_secret \
            = hkdf.derive_secret(master_secret, "c ap traffic", messages)
        self.server_application_traffic_secret \
            = hkdf.derive_secret(master_secret, "s ap traffic", messages)

        self.update_encryption_info(
            self.client_application_traffic_secret,
            self.server_application_traffic_secret,
            )

    def update_application_keys(self, messages: list[bytes]) -> None:
        """Generates application traffic keys

        Parameters
        ----------
        messages : list of bytes
            All handshake messages between and including `client_hello` and
            `server_finished` (without 5 byte record headers)
        """
        hkdf = self.crypto_suite.hkdf
        hash_length = self.crypto_suite.hash_length

        self.client_application_traffic_secret = hkdf.expand_label(
            self.client_application_traffic_secret, 'traffic upd', b'', hash_length)
        self.server_application_traffic_secret = hkdf.expand_label(
            self.server_application_traffic_secret, 'traffic upd', b'', hash_length)

        self.update_encryption_info(
            self.client_application_traffic_secret,
            self.server_application_traffic_secret,
            )

    def update_encryption_info(self, client_secret: bytes, server_secret: bytes) -> None:
        hkdf = self.crypto_suite.hkdf
        key_length = self.crypto_suite.key_length

        self.client_write_key \
            = hkdf.expand_label(client_secret, 'key', b'', key_length)
        self.client_write_iv \
            = hkdf.expand_label(client_secret, 'iv', b'', 12)
     
        self.server_write_key \
            = hkdf.expand_label(server_secret, 'key', b'', key_length)
        self.server_write_iv \
            = hkdf.expand_label(server_secret, 'iv', b'', 12)

    def client_finished_verify_data(self, messages: list[bytes]) -> bytes:
        return self.finished_verify_data(self.client_handshake_traffic_secret, messages)

    def server_finished_verify_data(self, messages: list[bytes]) -> bytes:
        return self.finished_verify_data(self.server_handshake_traffic_secret, messages)

    def finished_verify_data(self, secret: bytes, messages: list[bytes]) -> bytes:
        hkdf = self.crypto_suite.hkdf
        hash_function = self.crypto_suite.hash_function
        hash_length = self.crypto_suite.hash_length

        finished_key = hkdf.expand_label(secret, "finished", b'', hash_length)
        tomac = hash_function(b''.join(messages)).digest()
        verify_data = hkdf.hmac_hash(finished_key, tomac)

        return verify_data
