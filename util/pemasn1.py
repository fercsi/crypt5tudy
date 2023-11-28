#!/usr/bin/python3

from util.pem import Pem
from util.asn1 import *

class PemAsn1Object:
    pem_type: str
    content: Asn1Object

    def import_pem(self, pem_text: str) -> None:
        self.pem_type, ber_content = Pem.parse(pem_text)
        if ber_content[:7] == b'openssh':
            raise TypeError('information embedded in PEM data does not look to be ASN.1 object')
        self.content = Asn1.from_ber(ber_content)
        if self.pem_type in _POST_PROCESS:
            process = _POST_PROCESS[self.pem_type]
            if 'encapsulated' in process:
                for selector in process['encapsulated']:
                    self.content.process_encapsulated(selector=selector)
            if 'annotate' in process:
                self.content.annotate(*process['annotate'])

# annotate: 
# encapsulated: list of index-list. Each element in the list is an
#     encapsulation position in the main object. A position is a list of
#     indices, where each index is understood within a SEQUENCE deeper and
#     deeper in the structure.

# TODO: these are some experiments only! different algorithms have different data!
_POST_PROCESS = {
    'RSA PRIVATE KEY': {
        'annotate': ('RSA PRIVATE KEY', [
            ('version',),
            ('modulus',),
            ('publicExponent',),
            ('privateExponent',),
            ('prime1',),
            ('prime2',),
            ('exponent1',),
            ('exponent2',),
            ('coefficient',),
        ]),
    },
    'DSA PRIVATE KEY': {
        'annotate': ('DSA PRIVATE KEY', [
            ('version',),
            ('priv',),
            ('pub',),
            ('P',),
            ('Q',),
            ('G',),
        ]),
    },
    'DSA PARAMETERS': {
        'annotate': ('DSA PARAMETERS', [
            ('P',),
            ('Q',),
            ('G',),
        ]),
    },
    'PRIVATE KEY': { # RFC5958
        'encapsulated': [[2]],
        'annotate': ('PRIVATE_KEY', [
            ('version',),
            ('privateKeyAlgorithm',[
                ('algorithm',),
                ('parameters',),
            ]),
            ('privateKey',),
            ('attributes',),
        ]),
    },
    'PUBLIC KEY': {
        'encapsulated': [[1]],
        'annotate': ('PUBLIC KEY', [
            ('Algorithm', [('ID',), ('Parameters',)]),
            ('Key', )
        ])
    },
    'CERTIFICATE': { # RFC5280
        'encapsulated': [[0,6,1]],
        'annotate': ('CERTIFICATE', [
            ('tbsCertificate', [
                ('version', ),
                ('serialNumber', 'hex'),
                ('signature', [
                    ('algorithm', ),
                    ('parameters', ),
                ]),
                ('issuer', ),
                ('validity', [
                    ('notBefore', ),
                    ('notAfter', ),
                ]),
                ('subject', ),
                ('subjectPublicKeyInfo', [
                    ('algorithm', ),
                    ('subjectPublicKey', ),
                ]),
#>                ('issuerUniqueID', ), # optionals
#>                ('subjectUniqueID', ),
#>                ('extensions', ),
            ]),
            ('signatureAlgorithm', [
                ('algorithm', ),
                ('parameters', ),
            ]),
            ('signatureValue',),
        ])
    },
    'CERTIFICATE REQUEST': { # RFC2986
        'encapsulated': [[0,2,1]],
        'annotate': ('CERTIFICATE REQUEST', [
            ('certificationRequestInfo',[
                ('version',),
                ('subject',),
                ('subjectPKInfo',[
                    ('algorithm',[
                        ('algorithm',),
                        ('parameters',)
                    ]),
                    ('subjectPublicKey',)
                ]),
                ('attributes',),
            ]),
            ('signatureAlgorithm',[
                ('algorithm',),
                ('parameters',)
            ]),
            ('signature',)
        ])
    },

}
