#!/usr/bin/python3
# RFC8446

from tls.util import *
from .handshake import Handshake
from tls.extension import Extension, packExtensionList, unpackExtensionList

_CERTTYPE_IDS = {
    'x509': 0,
    'rawpublickey': 2,
    }

class Certificate(Handshake):
    def __init__(self, certificateType: int|str = 0):
        super().__init__()
        self.handshakeType = 11
        self.encryptedExtensionsTLSVersion = 0x0303
        self.setCertificateType(certificateType)
        self.certificateEntries = []

    def setCertificateType(self, certificateType: int|str) -> None:
        if isinstance(certificateType, str):
            certificateType = _CERTTYPE_IDS.get(certificateType.lower())
            if certificateType is None:
                raise NotImplementedError("Certificate type not supported")
        self.certificateType = certificateType

    def packHandshakeContent(self):
        crContext = packBytes(self.certificateRequestContext, 1)
        ents = (ent.pack() for ent in self.certificateEntries)
        return crContext + packBytesList(ents, 3)

    def unpackHandshakeContent(self, raw):
        pos = 0
        self.certificateRequestContext = unpackBytes(raw, pos, 1)
        pos += 1 + len(self.certificateRequestContext)
        endpos = pos + 3 + unpackU24(raw, pos)
        pos += 3
        while pos < endpos:
            entry = CertificateEntry(self.certificateType)
            start = pos
            pos += 3 + unpackU24(raw, pos)
            pos += 3 + unpackU24(raw, pos)
            entry.unpack(raw[start:pos])
            self.certificateEntries.append(entry)
#>        certificateList = unpackByteList(raw, pos, 3, 
#>        rawexts = unpackBytes(raw, pos, 2)
#>        self.unpackExtensions(rawexts)

    def represent(self, level: int = 0):
        crc = '~' if self.certificateRequestContext == b'' else self.certificateRequestContext.hex()
        ceStr = ''
        for entry in self.certificateEntries:
            ceStr += entry.represent(level + 2)
        return "Handshake-certificate:\n"       \
             + f"  CertificateRequestContent: {crc}\n" \
             + f"  CertificateEntries:\n" + ceStr

class CertificateEntry:
    certificateType: int
    certData: bytes|None # X509
    keyInfo: bytes|None # RawPublicKey, RFC7250
    extensions: list

    def __init__(self, certificateType: int):
        self.certificateType = certificateType
        self.certData = None
        self.keyInfo = None
        self.extensions = []

    def pack(self) -> bytes:
        c = self.certData if self.certData else self.keyInfo
        content = packBytes(c, 3)
        exts = packExtensionList(self.extensions, 3)
        packed = content + exts
        return packed

    def unpack(self, raw: bytes) -> None:
        content = unpackBytes(raw, 0, 3)
        if self.certificateType == 0:
            self.certData = content
        else:
            self.keyInfo = content
        pos = 3 + len(content)
        self.extensions = unpackExtensionList(raw, pos, 8, 3)

    def represent(self, level: int = 0) -> str:
        ind = '  '*level
        if self.certData is not None:
            text = ind + f'- CertData: {self.certData.hex()}\n'
        elif self.keyInfo is not None:
            text = ind + f'- ASN1_subjectPublicKeyInfo: {self.keyInfo.hex()}\n'
        extStr = ''
        for ext in self.extensions:
            extStr += ext.represent(level + 2)
        return text \
             + ind + "  Extensions:\n" + extStr
