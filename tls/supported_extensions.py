#!/usr/bin/python3

from .extension.ecpointformats import EcPointFormats
from .extension.encryptthenmac import EncryptThenMAC
from .extension.extendedmastersecret import ExtendedMasterSecret
from .extension.keyshare import KeyShare
from .extension.padding import Padding
from .extension.pskkeyexchangemodes import PskKeyExchangeModes
from .extension.servername import ServerName
from .extension.sessionticket import SessionTicket
from .extension.signaturealgorithms import SignatureAlgorithms
from .extension.supportedgroups import SupportedGroups
from .extension.supportedversions import SupportedVersions

from .extension.extension import UnknownExtension

_EXTENSION_HANDLERS = {
     0: ServerName, # RFC 6066
#>     1: MaxFragmentLength, # RFC 6066
#>     5: StatusRequest, # RFC 6066
    10: SupportedGroups, # RFC 8422, 7919
    11: EcPointFormats, #???
    13: SignatureAlgorithms, # RFC 8446
#>    14: UseSrtp, # RFC 5764
#>    15: Heartbeat, # RFC 6520
#>    16: ApplicationLayerProtocolNegotiation, # RFC 7301
#>    18: SignedCertificateTimestamp, # RFC 6962
#>    19: ClientCertificateType, # RFC 7250
#>    20: ServerCertificateType, # RFC 7250
    21: Padding, # RFC 7685
    22: EncryptThenMAC, #???
    23: ExtendedMasterSecret, #???
    35: SessionTicket, #???
#>    41: PreSharedKey, # RFC 8446
#>    42: EarlyData, # RFC 8446
    43: SupportedVersions, # RFC 8446
#>    44: Cookie, # RFC 8446
    45: PskKeyExchangeModes, # RFC 8446
#>    47: CertificateAuthorities, # RFC 8446
#>    48: OidFilters, # RFC 8446
#>    49: PostHandshakeAuth, # RFC 8446
#>    50: SignatureAlgorithmsCert, # RFC 8446
    51: KeyShare, # RFC 8446
    }
