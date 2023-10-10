#!/usr/bin/python3
# RFC8446

from tls.util import *
from .handshake import Handshake
from tls.extension import Extension, pack_extension_list, unpack_extension_list

_CERTTYPE_IDS = {
    'x509': 0,
    'rawpublickey': 2,
    }

class Certificate(Handshake):
    def __init__(self, certificate_type: int|str = 0):
        super().__init__()
        self.handshake_type = 11
        self.encrypted_extensions_tlsversion = 0x0303
        self.set_certificate_type(certificate_type)
        self.certificate_entries = []

    def set_certificate_type(self, certificate_type: int|str) -> None:
        if isinstance(certificate_type, str):
            certificate_type = _CERTTYPE_IDS.get(certificate_type.lower())
            if certificate_type is None:
                raise NotImplementedError("Certificate type not supported")
        self.certificate_type = certificate_type

    def pack_handshake_content(self):
        cr_context = pack_bytes(self.certificate_request_context, 1)
        ents = (ent.pack() for ent in self.certificate_entries)
        return cr_context + pack_bytes_list(ents, 3)

    def unpack_handshake_content(self, raw):
        pos = 0
        self.certificate_request_context = unpack_bytes(raw, pos, 1)
        pos += 1 + len(self.certificate_request_context)
        endpos = pos + 3 + unpack_u24(raw, pos)
        pos += 3
        while pos < endpos:
            entry = CertificateEntry(self.certificate_type)
            start = pos
            pos += 3 + unpack_u24(raw, pos)
            pos += 3 + unpack_u24(raw, pos)
            entry.unpack(raw[start:pos])
            self.certificate_entries.append(entry)
#>        certificate_list = unpack_byte_list(raw, pos, 3, 
#>        rawexts = unpack_bytes(raw, pos, 2)
#>        self.unpack_extensions(rawexts)

    def represent(self, level: int = 0):
        crc = '~' if self.certificate_request_context == b'' else self.certificate_request_context.hex()
        ce_str = ''
        for entry in self.certificate_entries:
            ce_str += entry.represent(level + 2)
        return "Handshake-certificate:\n"       \
             + f"  CertificateRequestContent: {crc}\n" \
             + f"  CertificateEntries:\n" + ce_str

class CertificateEntry:
    certificate_type: int
    cert_data: bytes|None # X509
    key_info: bytes|None # RawPublicKey, RFC7250
    extensions: list

    def __init__(self, certificate_type: int):
        self.certificate_type = certificate_type
        self.cert_data = None
        self.key_info = None
        self.extensions = []

    def pack(self) -> bytes:
        c = self.cert_data if self.cert_data else self.key_info
        content = pack_bytes(c, 3)
        exts = pack_extension_list(self.extensions, 3)
        packed = content + exts
        return packed

    def unpack(self, raw: bytes) -> None:
        content = unpack_bytes(raw, 0, 3)
        if self.certificate_type == 0:
            self.cert_data = content
        else:
            self.key_info = content
        pos = 3 + len(content)
        self.extensions = unpack_extension_list(raw, pos, 8, 3)

    def represent(self, level: int = 0) -> str:
        ind = '  '*level
        if self.cert_data is not None:
            text = ind + f'- CertData: {self.cert_data.hex()}\n'
        elif self.key_info is not None:
            text = ind + f'- ASN1_subjectPublicKeyInfo: {self.key_info.hex()}\n'
        ext_str = ''
        for ext in self.extensions:
            ext_str += ext.represent(level + 2)
        return text \
             + ind + "  Extensions:\n" + ext_str
