#!/usr/bin/python3

from abc import ABC, abstractmethod
import tls
from .util import *

class Connect(ABC):
    def __init__(self, *, hostname: str, port: int = 443, timeout: float = 30.0, debug_level: int = 0):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.debug_level = debug_level
        debug(2, debug_level, f"Connection parameters: {hostname}:{port}, timeout: {timeout}")
        self.decrypt_received = False
        self.encrypt_sending = False
        self.socket = None

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
        record = self.receive_pack()
        # TODO: Now assume, that 1 record is 1 message
        content_type = unpack_u8(record)
        length = unpack_u16(record, 3)
        message = tls.unpack_message(content_type, record, 5, length, debug_level=self.debug_level)
        if isinstance(message, tls.ApplicationData) and self.decrypt_received:
            crs = self.crypto_suite
            cs = crs.cipher_suite
            cipher_text = message.content[:-cs.t_len]
            auth_data = record[:5]
            auth_tag_received = message.content[-cs.t_len:]
            plain_text, auth_tag_calculated = crs.aead.decrypt(cipher_text, auth_data)
            if auth_tag_received != auth_tag_calculated:
                raise KeyError('Key negotiation failed')
            content_type = unpack_u8(plain_text[-1:])
            content = plain_text[:-1]
            content_length = len(plain_text)
            message = tls.unpack_message(content_type, content, debug_level=self.debug_level)
        if isinstance(message, tls.Alert):
            if message.is_fatal():
                self.disconnect()
                raise ConnectionAbortedError(f"Server reported fatal error: {message.error_str()}")
        return message

    def receive_pack(self) -> bytes:
        head = self.receive_bytes(5)
        body = self.receive_bytes(int.from_bytes(head[3:], 'big'))
        return head + body

    def receive_bytes(self, cnt: int = 65536) -> bytes:
        data = b''
        while cnt > 0:
            read = self.socket.recv(min(cnt, 32768))
            if not read:
                raise BrokenPipeError("Error receiving data")
            cnt -= len(read)
            data += read
        debug(4, self.debug_level, f"{len(data)} bytes TCP data received")
        return data
