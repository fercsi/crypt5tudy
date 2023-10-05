#!/usr/bin/python3
# RFC8446 (RFC5246) No affect in TLS1.3

from tls.util import *
from tls.record import Record

LEVEL_IDS: dict[str, int] = {
    'warning': 1,
    'fatal': 2,
    }

DESCRIPTION_IDS: dict[str, int] = {
    'close_notify': 0,
    'unexpected_message': 10,
    'bad_record_mac': 20,
    'record_overflow': 22,
    'handshake_failure': 40,
    'bad_certificate': 42,
    'unsupported_certificate': 43,
    'certificate_revoked': 44,
    'certificate_expired': 45,
    'certificate_unknown': 46,
    'illegal_parameter': 47,
    'unknown_ca': 48,
    'access_denied': 49,
    'decode_error': 50,
    'decrypt_error': 51,
    'protocol_version': 70,
    'insufficient_security': 71,
    'internal_error': 80,
    'inappropriate_fallback': 86,
    'user_canceled': 90,
    'missing_extension': 109,
    'unsupported_extension': 110,
    'unrecognized_name': 112,
    'bad_certificate_status_response': 113,
    'unknown_psk_identity': 115,
    'certificate_required': 116,
    'no_application_protocol': 120,
    }

class Alert(Record):
    def __init__(self, level: int|str = 0, description: int|str = 0):
        super().__init__()
        self.recordType = 21
        self.setLevel(level)
        self.setDescription(description)

    def setLevel(self, level: str|int) -> None:
        n = level
        self.level = LEVEL_IDS[n] if isinstance(n, str) else n

    def setDescription(self, description: str|int) -> None:
        n = description
        self.description = DESCRIPTION_IDS[n] if isinstance(n, str) else n

    def packRecordContent(self) -> bytes:
        return packU8(self.level) + packU8(self.description)

    def unpackRecordContent(self, raw: bytes) -> None:
        self.level = unpackU8(raw, 0)
        self.description = unpackU8(raw, 1)

    def represent(self, level: int = 0):
        ind = '  '*level
        text = ind + 'Alert:\n'
        revlut = {}
        for k, v in LEVEL_IDS.items():
            revlut[v] = k
        text += ind + f'  Level: {revlut[self.level]}\n'
        revlut = {}
        for k, v in DESCRIPTION_IDS.items():
            revlut[v] = k
        text += ind + f'  Description: {revlut[self.description]}\n'
        return text
