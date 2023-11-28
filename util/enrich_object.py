#!/usr/bin/python3

from util.asn1 import Asn1Object

def enrich_object(asn1_object: Asn1Object, id: str) -> None:
    if id not in _OBJECT_INFO:
        return
    info = _OBJECT_INFO[id]
    if 'encapsulated' in info:
        for selector in info['encapsulated']:
            asn1_object.process_encapsulated(selector=selector)
    if 'annotate' in info:
        asn1_object.annotate(*info['annotate'])


# annotate: 
# encapsulated: list of index-list. Each element in the list is an
#     encapsulation position in the main object. A position is a list of
#     indices, where each index is understood within a SEQUENCE deeper and
#     deeper in the structure.

# TODO: these are some experiments only! different algorithms have different data!
_OBJECT_INFO = {
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
    'PRIVATE KEY': { # RFC5958, OID 2.16.840.1.101.2.1.2.78.5
        'encapsulated': [[2]],
        'annotate': ('PRIVATE KEY', [
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
    'x509_certificate': { # RFC5280
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
