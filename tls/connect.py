#!/usr/bin/python3

from abc import ABC, abstractmethod
from queue import Queue
import tls
from .types import ContentType
from util.serialize import *
from util.verbose import *

class Connect(ABC):
    def __init__(self, *, hostname: str, port: int = 443, timeout: float = 30.0, verbosity: int = 0):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.verbosity = verbosity
        verbose(2, verbosity, f"Connection parameters: {hostname}:{port}, timeout: {timeout}")
        self.decrypt_received = False
        self.encrypt_sending = False
        self.socket = None
        self.handshake_fragments = bytearray()
        self.application_data = bytearray()
        self.message_queue = Queue()

    def __del__(self):
        self.disconnect()

    @abstractmethod
    def connect():
        pass

    def disconnect(self):
        if self.socket:
            try: # Don't care if not successful
                self.socket.close()
            except:
                pass
            self.socket = None

    def send(self, text: bytes|str):
        if isinstance(text, str):
            text = text.encode()
        self.send_message(tls.ApplicationData(text))
        verbose(1, self.verbosity, f"{len(text)} bytes TLS data sent")

    def receive(self, size: int = 0) -> bytes|str:
        if size:
            while len(self.application_data) < size:
                self.receive_record()
            application_data = self.application_data[:size]
            self.application_data = self.application_data[size:]
        else:
            while len(self.application_data) == 0:
                self.receive_record()
            application_data = self.application_data
            self.application_data = bytearray()
        if self.text_mode:
            application_data = (application_data).decode()
        else:
            application_data = bytes(application_data)
        return application_data

    def prepare_message(self, message: tls.Message) -> bytes:
        raw_content = message.pack()
        if self.encrypt_sending:
            crs = self.crypto_suite
            cs = crs.cipher_suite
            plain_text = raw_content[5:] + raw_content[:1]
            new_length = len(plain_text) + cs.t_len
            message_head = b'\x17' + raw_content[1:3] + new_length.to_bytes(2, 'big')
            cipher_text, auth_tag = crs.aead.encrypt(plain_text, message_head)
            raw_content = message_head + cipher_text + auth_tag
        return raw_content

    def send_message(self, message: tls.Message) -> bytes:
        raw_content = self.prepare_message(message)
        self.send_pack(raw_content)
        return raw_content

    def send_pack(self, content: bytes) -> None:
        self.socket.sendall(content)

    def receive_message(self) -> tls.Message:
        while self.message_queue.empty():
            self.receive_record()
        message = self.message_queue.get()
        return message

    def receive_record(self) -> bytes:
        record_head = self.receive_bytes(5)
        content_type = unpack_u8(record_head)
        length = unpack_u16(record_head, 3)
        fragment = self.receive_bytes(length)
        if content_type == ContentType.application_data and self.decrypt_received:
            crs = self.crypto_suite
            cs = crs.cipher_suite
            cipher_text = fragment[:-cs.t_len]
            auth_data = record_head
            auth_tag_received = fragment[-cs.t_len:]
            plain_text, auth_tag_calculated = crs.aead.decrypt(cipher_text, auth_data)
            if auth_tag_received != auth_tag_calculated:
                raise KeyError('Key negotiation failed')
            content_type = unpack_u8(plain_text[-1:])
            fragment = plain_text[:-1]
            length = len(fragment)

        pos = 0
        if content_type == ContentType.handshake:
            self.handshake_fragments += fragment
            hs_fragment_length = len(self.handshake_fragments)
            while pos < hs_fragment_length:
                if pos + 4 > hs_fragment_length:
                    break
                hs_length = unpack_u24(self.handshake_fragments, pos+1)
                if pos + 4 + hs_length > hs_fragment_length:
                    break
                message = tls.unpack_message(content_type, self.handshake_fragments, pos, hs_length+4, verbosity=self.verbosity)
                self.message_queue.put(message)
                pos += 4 + hs_length
            self.handshake_fragments = self.handshake_fragments[pos:]
        elif content_type == ContentType.application_data:
            self.application_data += fragment
        elif content_type == ContentType.alert:
            while pos < length:
                message = tls.unpack_message(content_type, fragment, pos, 2, verbosity=self.verbosity)
                self.message_queue.put(message)
                pos += 2
        else: # change_cipher_spec messages are eliminated, too
            pass

    def receive_bytes(self, cnt: int = 65536) -> bytes:
        data = b''
        while cnt > 0:
            read = self.socket.recv(min(cnt, 32768))
            if not read:
                raise BrokenPipeError("Error receiving data")
            cnt -= len(read)
            data += read
        verbose(4, self.verbosity, f"{len(data)} bytes TCP data received")
        return data
