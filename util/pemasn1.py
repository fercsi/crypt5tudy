#!/usr/bin/python3

from util.pem import Pem
from util.asn1 import *

class PemAsn1Object:
    pem_type: str
    content: Asn1Object

    def import_pem(self, pem_text: str) -> None:
        self.pem_type, ber_content = Pem.parse(pem_text)
        self.content = Asn1.from_ber(ber_content)
        if self.pem_type in _POST_PROCESS:
            process = _POST_PROCESS[self.pem_type]
            if 'encapsulated' in process:
                for pos in process['encapsulated']:
                    content = self.content
                    for idx in pos:
                        content = content.content[idx]
                    content.process_encapsulated()
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
            ('modulus', 'block'),
            ('publicExponent',),
            ('privateExponent', 'block'),
            ('prime1', 'block'),
            ('prime2', 'block'),
            ('exponent1', 'block'),
            ('exponent2', 'block'),
            ('coefficient', 'block'),
        ]),
    },
    'DSA PRIVATE KEY': {
        'annotate': ('DSA PRIVATE KEY', [
            ('version',),
            ('priv', 'block'),
            ('pub', 'block'),
            ('P', 'block'),
            ('Q', 'block'),
            ('G', 'block'),
        ]),
    },
    'DSA PARAMETERS': {
        'annotate': ('DSA PARAMETERS', [
            ('P', 'block'),
            ('Q', 'block'),
            ('G', 'block'),
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
            ('Key (encapsulated)', [
                ('Key', [
                    ('Modulus',),
                    ('Exponent',),
                ])
            ])
        ])
    },
    'CERTIFICATE REQUEST': { # RFC2986
        'encapsulated': [[2], [0,2,1]],
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
