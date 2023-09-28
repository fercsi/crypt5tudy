#!/usr/bin/python3

from .extension.ecpointformats import EcPointFormats
from .extension.extendedmastersecret import ExtendedMasterSecret
from .extension.keyshare import KeyShare
from .extension.pskkeyexchangemodes import PskKeyExchangeModes
from .extension.servername import ServerName
from .extension.sessionticket import SessionTicket
from .extension.signaturealgorithms import SignatureAlgorithms
from .extension.supportedgroups import SupportedGroups
from .extension.supportedversions import SupportedVersions

from .extension.extension import UnknownExtension

_EXTENSION_HANDLERS = {
     0: ServerName,
    10: SupportedGroups,
    11: EcPointFormats,
    13: SignatureAlgorithms,
    23: ExtendedMasterSecret,
    35: SessionTicket,
    43: SupportedVersions,
    45: PskKeyExchangeModes,
    51: KeyShare,
    }
