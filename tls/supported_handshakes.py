#!/usr/bin/python3

from .handshake.certificate import Certificate
from .handshake.certificateverify import CertificateVerify
from .handshake.clienthello import ClientHello
from .handshake.encryptedextensions import EncryptedExtensions
from .handshake.finished import Finished
from .handshake.newsessionticket import NewSessionTicket
from .handshake.serverhello import ServerHello

from .handshake import Handshake, UnknownHandshake

_HANDSHAKE_HANDLERS = {
    1: ClientHello,
    2: ServerHello,
    4: NewSessionTicket,
#>    5: EndOfEarlyData,
    8: EncryptedExtensions,
    11: Certificate,
#>    13: CertificateRequest,
    15: CertificateVerify,
    20: Finished,
#>    24: KeyUpdate,
#>    254: MessageHash,        
    }
