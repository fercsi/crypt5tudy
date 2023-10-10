#!/usr/bin/python3

from .record import Record, UnknownRecord
from .handshake import Handshake, UnknownHandshake
from .supported_handshakes import *
from .supported_handshakes import _HANDSHAKE_HANDLERS
from .changecipherspec import ChangeCipherSpec
from .alert import Alert
from .applicationdata import ApplicationData
from .util import *

_RECORD_HANDLERS = {
    20: ChangeCipherSpec,
    21: Alert,
    22: Handshake,
    23: ApplicationData,
    }

def unpack_record(raw: bytes) -> Record:
    return unpack_records(raw, 1)[0]

def unpack_records(raw: bytes, limit: int = 0) -> [Record]:
    pos = 0
    records = []
    if limit == 0:
        limit = len(raw)
    while pos < len(raw) and len(records) < limit:
        record_length = 5 + unpack_u16(raw, pos+3)
        record_content = raw[pos:pos+record_length]
        record_type = unpack_u8(record_content, 0)
        record_tlsversion = unpack_u16(record_content, 11)
        record_handler = _RECORD_HANDLERS.get(record_type)
        if record_handler is None:
            record = UnknownRecord(record_type)
        else:
            record = record_handler()
        if isinstance(record, Handshake):
            handshake_type = unpack_u8(record_content, 5)
            handshake_handler = _HANDSHAKE_HANDLERS.get(handshake_type)
            if handshake_handler is None:
                record = UnknownHandshake(handshake_type)
            else:
                record = handshake_handler()
        record.record_tlsversion = record_tlsversion
        record.unpack(record_content)
        records.append(record)
        pos += record_length
    return records
