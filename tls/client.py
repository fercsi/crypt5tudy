#!/usr/bin/python3

import socket

import tls
import crypto

from .connect import Connect
from .message import Message
from .ecdh import ECDH
from .ffdh import FFDH
from .groupinfo import *
from .keyexchange import KeyExchange
from util.verbose import *

class Client(Connect):
    """
    Limitations
    -----------
    - Key share group is not negotiated (selectable by client, though)
    """
    def __init__(self, *,
            hostname: str, port: int = 443, timeout: float = 30.0,
            key_share_group: str = 'x25519',
            mode: str = 't',
            verbosity: int = 0,
        ):
        verbose(1, verbosity, f"Initialize TLS connection...")
        super().__init__(hostname=hostname, port=port, timeout=timeout,
                                                     verbosity=verbosity)
        self.set_group_info(key_share_group)
        self.text_mode = mode == 't'
        verbose(2, verbosity, f"Set mode to {'text' if mode == 't' else 'binary'}")
        self.session_tickets = []

    def set_group_info(self, group_info: int|str|tuple):
        if isinstance(group_info, str):
            self.group_info = GROUP_INFO_BY_STR[group_info]
        elif isinstance(group_info, int):
            self.group_info = GROUP_INFO_BY_ID[group_info]
        elif isinstance(group_info, (WeierstrassGroup, MontgomeryGroup, FFDHGroup)):
            self.group_info = group_info
        verbose(2, self.verbosity, f"Key Share Group parameters: {self.group_info}")

        if isinstance(self.group_info, FFDHGroup): # Finite field
            self.key_manager = FFDH(self.group_info)
        else: # Elliptic curve group
            self.key_manager = ECDH(self.group_info)

    def connect(self):
        verbose(1, self.verbosity, "Send client_hello...")
        self.send_client_hello()
        verbose(1, self.verbosity, "Process server response...")
        self.process_server_response()
        verbose(1, self.verbosity, "Client finishes handshake...")
        self.finish_client_handshake()
        verbose(1, self.verbosity, "Handshake finished")

    def send_client_hello(self) -> None:
        self.socket = socket.create_connection((self.hostname, self.port), self.timeout)
        client_hello = self.mk_client_hello()
        content = self.send_message(client_hello)[5:]
        self.handshakes = [content]

    def process_server_response(self) -> None:
        goon = True
        while goon:
            message = self.receive_message()
            message.verbosity = self.verbosity
            if isinstance(message, tls.Alert): # Fatal alerts killed the app by now
                print(f"Server reported warning: {message.error_str()}")
            elif isinstance(message, tls.Handshake):
                self.process_handshake(message)
                if isinstance(message, tls.Finished):
                    goon = False
            elif isinstance(message, tls.ChangeCipherSpec):
                self.decrypt_received = True
            elif isinstance(message, tls.ApplicationData):
                raise ConnectionError('No data expected in handshaking phase')
            else:
                raise NotImplementedError("Message type not implemented")

    def finish_client_handshake(self) -> None:
        # SEND further client handshake messages
        # Change to encrypted mode
        messages = self.prepare_message(tls.ChangeCipherSpec())
        self.encrypt_sending = True

        # Send "Client Finished"
        verify_data = self.key_exchange.client_finished_verify_data(self.handshakes)
        messages += self.prepare_message(tls.Finished(verify_data))

        self.send_pack(messages)
        # Handshake finidhed

        # calculate application keys:
        kex = self.key_exchange
        crs = self.crypto_suite
        kex.generate_application_keys(self.handshakes)
        crs.set_my_key(kex.client_write_key)
        crs.set_peer_key(kex.server_write_key)
        crs.set_my_nonce(kex.client_write_iv)
        crs.set_peer_nonce(kex.server_write_iv)

    def process_handshake(self, message: Message) -> None:
        message_content = message.raw_content
        rec_type = type(message)
        if rec_type is tls.ServerHello:
            self.cipher_suite = message.cipher_suite
            self.crypto_suite = crypto.CryptoSuite(self.cipher_suite)
            self.key_exchange = KeyExchange(self.crypto_suite)
            for extension in message.extensions:
                ext_type = type(extension)
                if ext_type is tls.SupportedVersions:
                    self.tls_version = extension.versions[0]
                if ext_type is tls.KeyShare:
                    group = extension.shares[0].group
                    self.peer_public_key = extension.shares[0].key_exchange
                    if self.group_info.id != group:
                        raise TypeError('Key exchange negotiation failed')
            shared_secret = self.key_manager.create_secret(self.private_key, self.peer_public_key)
            kex = self.key_exchange
            crs = self.crypto_suite
            kex.generate_handshake_keys(shared_secret, self.handshakes + [message_content])
            crs.set_my_key(kex.client_write_key)
            crs.set_peer_key(kex.server_write_key)
            crs.set_my_nonce(kex.client_write_iv)
            crs.set_peer_nonce(kex.server_write_iv)
            self.decrypt_received = True
        elif rec_type is tls.EncryptedExtensions:
            # TODO: maybe some invalid servername, but usually nothing
            pass
        elif rec_type is tls.Certificate:
            # TODO check certificate
            pass
        elif rec_type is tls.CertificateVerify:
            # TODO verify certificate
            pass
        elif rec_type is tls.Finished:
            verify_data = self.key_exchange.server_finished_verify_data(self.handshakes)
            if message.verify_data != verify_data:
                raise ConnectionError('Handshake verification failed')
        elif rec_type is tls.NewSessionTicket:
            self.session_tickets.append({
                'lifetime': message.ticket_lifetime,
                'age_add': message.ticket_age_add,
                'nonce': message.ticket_nonce,
                'ticket': message.ticket,
            })
        else:
            raise NotImplementedError(f'Unknown handshake message received {message.handshake_type}')
        self.handshakes.append(message_content)
        verbose(1, self.verbosity, f"Handshake message {type(message).__name__} received")

    def mk_client_hello(self):
        ch = tls.ClientHello([
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            ])
        e = tls.ServerName(self.hostname)
        ch.add_extension(e)
        # TODO: Currently only a single group is supported for key share
        e = tls.SupportedGroups([
            self.group_info.id
            ])
        ch.add_extension(e)
        e = tls.SignatureAlgorithms([
            'RSA-PSS-RSAE-SHA256'
            ])
        ch.add_extension(e)
        e = tls.SupportedVersions([
            'tls1.3'
            ])
        ch.add_extension(e)
        e = tls.PskKeyExchangeModes([
            'psk_dhe_ke'
            ])
        ch.add_extension(e)
        self.private_key, self.public_key = self.key_manager.generate_key_pair()
        e = tls.KeyShare(self.group_info.id, self.public_key)
        ch.add_extension(e)
        return ch

