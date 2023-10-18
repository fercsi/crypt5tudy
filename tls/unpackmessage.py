#!/usr/bin/python3
# 17 03 03 ll ll <hs1> <hs2> 16 auth_tah

from .message import Message, UnknownMessage
from .handshake import Handshake, UnknownHandshake
from .supported_handshakes import *
from .supported_handshakes import _HANDSHAKE_HANDLERS
from .changecipherspec import ChangeCipherSpec
from .alert import Alert
from .applicationdata import ApplicationData
from .util import *
from .types import ContentType

_MESSAGE_HANDLERS = {
    ContentType.change_cipher_spec: ChangeCipherSpec,
    ContentType.alert: Alert,
    ContentType.handshake: Handshake,
    ContentType.application_data: ApplicationData,
    }

def unpack_message(content_type: int, raw: bytes, pos: int = 0, length: int|None = None, *, debug_level: int = 0) -> Message:
    if length is None:
        if content_type == ContentType.handshake:
            length = 4 + unpack_u24(raw, pos+1)
        elif content_type == ContentType.alert:
            length = 2
        elif content_type == ContentType.change_cipher_spec:
            length = 2
        else:
            length = len(raw) - pos
    raw_content = raw[pos:pos+length]
    message_handler = _MESSAGE_HANDLERS.get(content_type)
    if message_handler is None:
        message = UnknownMessage(message_type)
    else:
        message = message_handler()
    if isinstance(message, Handshake):
        handshake_type = unpack_u8(raw_content)
        handshake_handler = _HANDSHAKE_HANDLERS.get(handshake_type)
        if handshake_handler is None:
            message = UnknownHandshake(handshake_type)
        else:
            message = handshake_handler()
    message.debug_level = debug_level
    message.unpack(raw_content)
    return message
