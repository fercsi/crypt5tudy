#!/usr/bin/python3

from .record import Record, UnknownRecord
from .handshake import Handshake, UnknownHandshake
from .supported_handshakes import *
from .supported_handshakes import _HANDSHAKE_HANDLERS
from .util import *

_RECORD_HANDLERS = {
#>    20: ChangeCipherSpec,
#>    21: Alert,
    22: Handshake,
#>    23: ApplicationData,
    }
#>_HANDSHAKE_HANDLERS = {
#>    1: ClientHello,
#>    2: ServerHello,
#>#>    4: NewSessionTicket,
#>#>    5: EndOfEarlyData,
#>#>    8: EncryptedExtensions,
#>#>    11: Certificate,
#>#>    13: CertificateRequest,
#>#>    15: CertificateVerify,
#>#>    20: Finished,
#>#>    24: KeyUpdate,
#>#>    254: MessageHash,        
#>    }

def unpackRecord(raw: bytes) -> Record:
    recordType = unpackU8(raw, 0)
    recordTLSVersion = unpackU16(raw, 1)
    recordContent = raw[0:5+unpackU16(raw, 3)]
#>    recordContent = unpackBytes(raw, 3, 2)
    recordHandler = _RECORD_HANDLERS.get(recordType)
    if recordHandler is None:
        record = UnknownRecord(recordType)
    else:
        record = recordHandler()
    if isinstance(record, Handshake):
        handshakeType = unpackU8(raw, 5)
        handshakeHandler = _HANDSHAKE_HANDLERS.get(handshakeType)
        if handshakeHandler is None:
            record = UnknownHandshake(handshakeType)
        else:
            record = handshakeHandler()
    record.recordTLSVersion = recordTLSVersion
    record.unpack(recordContent)
    return record
