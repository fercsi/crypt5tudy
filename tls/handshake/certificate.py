#!/usr/bin/python3
# RFC8446, RFC3280, RFC5280
# https://www.itu.int/wftp3/Public/t/fl/ietf/rfc/rfc3280/PKIX1Explicit88.html

import re
from util.serialize import *
from util.asn1 import Asn1, Asn1Object, Asn1Boolean
from util.enrich_object import enrich_object
from tls.types import HandshakeType
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
            rawcert = unpack_bytes(raw, pos, 3)
            entry.unpack(rawcert)
            pos += 3 + unpack_u24(raw, pos)
            entry.extensions = unpack_extension_list(raw, pos,
                                        HandshakeType.certificate, lensize=2)
            pos += 2 + unpack_u16(raw, pos)
            self.certificate_entries.append(entry)

    def represent(self, level: int = 0):
        crc = '~' if self.certificate_request_context == b'' else self.certificate_request_context.hex()
        ce_str = ''
        for entry in self.certificate_entries:
            ce_str += entry.represent(level + 2)
        return "Handshake-certificate:\n"       \
             + f"  CertificateRequestContent: {crc}\n" \
             + f"  CertificateEntries:\n" + ce_str

# TODO: Create a separate certificate module (with submodules)

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

    def unpack(self, cert: bytes) -> None:
        if self.certificate_type == 0:
            self.cert_data = cert
        else:
            self.key_info = cert

    def get_cert_info(self):
        obj = self.get_cert_object()
        info = {}
        tbsc = obj[0]
        info['version'] = 'v' + str(tbsc[0][0].value + 1)
        info['serialNumber'] = tbsc[1].value
        info['signature'] = self._process_algorithm(tbsc[2])
        issuer = {}
        for seq in tbsc[3]:
            name = seq[0][0].oid_name
            value = seq[0][1].value
            issuer[name] = value
        info['issuer'] = issuer
        info['validity'] = {
            'notBefore': tbsc[4][0].value,
            'notAfter': tbsc[4][1].value,
        }
        subject = {}
        for seq in tbsc[5]:
            name = seq[0][0].oid_name
            value = seq[0][1].value
            subject[name] = value
        info['subject'] = subject
        algorithm = self._process_algorithm(tbsc[6][0])
        if algorithm['algorithm'] == 'rsaEncryption':
            pubkey = {
                'n': tbsc[6][1][0][0].value,
                'e': tbsc[6][1][0][1].value,
            }
        elif algorithm['algorithm'] == 'ecPublicKey':
            data = tbsc[6][1].data
            size = len(data) >> 1
            pubkey = {
                'x': int.from_bytes(data[1:1+size]),
                'y': int.from_bytes(data[1+size:]),
            }
        else:
            pubkey = tbsc[6][1].represent()
        info['subjectPublicKeyInfo'] = {
            'algorithm': algorithm,
            'subjectPublicKey': pubkey
        }

        for obj in tbsc[7:]:
            type_id = obj.info().type_id
            if type_id == 1: # issuerUniqueID
                obj.format = hex
                info['issuerUniqueID'] = obj.represent()
            if type_id == 2: # subjectUniqueID
                obj.format = hex
                info['subjectUniqueID'] = obj.represent()
            if type_id == 3: # extensions
                # https://www.gradenegger.eu/en/basics-the-key-usage-certificate-extension/
                extensions = []
                for seq in obj[0]:
                    name = seq[0].oid_name
                    vpos = 1
                    if isinstance(seq[1], Asn1Boolean):
                        vpos = 2
                        critical = seq[1].value
                    else:
                        critical = False
                    seq[vpos].process_encapsulated()
                    processor = _CERT_EXT_PROCESSOR.get(name, None)
                    if processor is None:
                        value = str(seq[vpos][0])
                    else:
                        value = processor(seq[vpos][0])
                    extensions.append({
                        'name': name,
                        'critical': critical,
                        'value': value,
                    })
#>                    print(name, critical)
#>                    print(seq[vpos])
                info['extensions'] = extensions
        return info

    def _process_algorithm(self, obj: Asn1Object):
        signature_algorithm  = obj[0].oid_name
        # TODO Signature parameters: RFC 3279, 4055, 4491; 5246, 4492
        algorithm = {
            'algorithm': signature_algorithm,
            'parameters': None, #TODO
        }
        return algorithm

    def get_cert_object(self):
        obj = Asn1.from_ber(self.cert_data)
        enrich_object(obj, 'x509_certificate')
        return obj

    def represent(self, level: int = 0) -> str:
        ind = '  '*level
        if self.cert_data is not None:
            cert_info = self.get_cert_info()
            text = ind + f'- CertData:\n{cert_info._represent(level+1)}\n'
        elif self.key_info is not None:
            text = ind + f'- ASN1_subjectPublicKeyInfo: {self.key_info.hex()}\n'
        ext_str = ''
        for ext in self.extensions:
            ext_str += ext.represent(level + 2)
        return text \
             + ind + "  Extensions:\n" + ext_str

def _ext_authorityKeyIdentifier(obj: Asn1Object):
    # RFC5280, 4.2.1.1
    info = {}
    for o in obj:
        type_id = o.info().type_id
        if type_id == 0:
            o.format = 'hex'
            info['keyIdentifier'] = o.data.hex()
        elif type_id == 1:
            info['authorityCertIssuer'] = o.represent()
        elif type_id == 2:
            info['authorityCertSerialNumber'] = o.represent()
    return info

def _ext_subjectKeyIdentifier(obj: Asn1Object):
    # RFC5280, 4.2.1.2
    obj.format = 'hex'
    return obj.represent()[2:]

_EXT_KEYUSAGE_FLAGS = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
]
def _ext_keyUsage(obj: Asn1Object):
    # RFC5280, 4.2.1.3
    flags = []
    for i in range(obj.length):
        if obj[i]:
            flags.append(_EXT_KEYUSAGE_FLAGS[i])
    return flags

def _ext_certificatePolicies(obj: Asn1Object):
    # RFC5280, 4.2.1.4
    info = []
    for o in obj:
        oid = o[0].oid_name
        pq = None
        if len(o) > 1:
            pq = []
            for q in o[1]:
                pq.append({
                    'policyQualifierId': q[0].oid_name,
                    'qualifier': q[1].value,
                })
#>            pq = [q.represent() for q in o[1]]
        info.append({
            'policyIdentifier': oid,
            'policyQualifiers': pq
        })
    return info

_GENERALNAME = [
    'otherName',
    'rfc822Name',
    'dNSName',
    'x400Address',
    'directoryName',
    'ediPartyName',
    'uniformResourceIdentifier',
    'iPAddress',
    'registeredID',
]
def _ext_subjectAltName(obj: Asn1Object):
    # RFC5280, 4.2.1.6
    info = []
    for o in obj:
        type_id = o.info().type_id
        gname = {'type': _GENERALNAME[type_id]}
        if type_id in [2, 3, 6]:
            gname['value'] = o.data.decode()
        else: # TODO
            gname['value'] = o.represent()
        info.append(gname)
    return info

def _ext_basicConstraints(obj: Asn1Object):
    # RFC5280, 4.2.1.9
    c = { 'cA': False }
    for o in obj:
        if isinstance(o, Asn1Boolean):
            c['cA'] = o.value
        else:
            c['pathLenConstraint'] = o.value
    return c

def _ext_extKeyUsage(obj: Asn1Object):
    # RFC5280, 4.2.1.12
    return [o.oid_name for o in obj]

_REASONFLAGS = [
    'unused',
    'keyCompromise',
    'cACompromise',
    'affiliationChanged',
    'superseded',
    'cessationOfOperation',
    'certificateHold',
    'privilegeWithdrawn',
    'aACompromise',
]
def _ext_cRLDistributionPoints(obj: Asn1Object):
    # RFC5280, 4.2.1.13
    info = []
    for dp in obj:
        dpinfo = {}
        for o in dp:
            type_id = o.info().type_id
            if type_id == 0:
                fullname = [_general_name(g) for g in o[0]]
#>                rel = TODO
                dpinfo['distributionPoint'] = {
                    'fullname': fullname,
#>                    'nameRelativeToCRLIssuer': rel,
                }
                pass
            elif type_id == 1:
                pass
            elif type_id == 2:
                dpinfo['cRLIssuer'] = [_general_name(g) for g in o]
        info.append(dpinfo)
    return info

def _general_name(obj: Asn1Object):
    type_id = obj.info().type_id
    gname = {'type': _GENERALNAME[type_id]}
    if type_id in [2, 3, 6]:
        gname['value'] = obj.data.decode()
    else: # TODO
        gname['value'] = obj.represent()
    return gname

def _ext_authorityInfoAccess(obj: Asn1Object):
    # RFC5280, 4.2.2.1
    info = []
    for o in obj:
        oid = o[0].oid_name
        type_id = o[1].info().type_id
        gname = {'type': _GENERALNAME[type_id]}
        if type_id in [2, 3, 6]:
            gname['value'] = o[1].data.decode()
        else: # TODO
            gname['value'] = o[1].represent()
        info.append({
            'accessMehtod': oid,
            'accessLocation': gname,
        })
    return info

_CERT_EXT_PROCESSOR = {
    'authorityKeyIdentifier': _ext_authorityKeyIdentifier, # 1.1
    'subjectKeyIdentifier': _ext_subjectKeyIdentifier, # 1.2
    'keyUsage': _ext_keyUsage, # 1.3
    'certificatePolicies': _ext_certificatePolicies, # 1.4
    'subjectAltName': _ext_subjectAltName, # 1.6
    'basicConstraints': _ext_basicConstraints, # 1.9
    'extKeyUsage': _ext_extKeyUsage, # 1.12
    'cRLDistributionPoints': _ext_cRLDistributionPoints, # 1.13
    'authorityInfoAccess': _ext_authorityInfoAccess, # 2.1
}
