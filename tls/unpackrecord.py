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

def unpackRecord(raw: bytes) -> Record:
    return unpackRecords(raw, 1)[0]

def unpackRecords(raw: bytes, limit: int = 0) -> [Record]:
    pos = 0
    records = []
    if limit == 0:
        limit = len(raw)
    while pos < len(raw) and len(records) < limit:
        recordLength = 5 + unpackU16(raw, pos+3)
        recordContent = raw[pos:pos+recordLength]
        recordType = unpackU8(recordContent, 0)
        recordTLSVersion = unpackU16(recordContent, 11)
        recordHandler = _RECORD_HANDLERS.get(recordType)
        if recordHandler is None:
            record = UnknownRecord(recordType)
        else:
            record = recordHandler()
        if isinstance(record, Handshake):
            handshakeType = unpackU8(recordContent, 5)
            handshakeHandler = _HANDSHAKE_HANDLERS.get(handshakeType)
            if handshakeHandler is None:
                record = UnknownHandshake(handshakeType)
            else:
                record = handshakeHandler()
        record.recordTLSVersion = recordTLSVersion
        record.unpack(recordContent)
        records.append(record)
        pos += recordLength
    return records
