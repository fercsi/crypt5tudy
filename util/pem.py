#!/usr/bin/python3
# RFC7468

import base64

class Pem:
    @staticmethod
    def parse(text: str) -> bytes:
        lines = text.split('\n')
        state = 'search'
        b64 = ''
        pem_type = None
        for line in lines:
            if state == 'search':
                if line[:11] == '-----BEGIN ':
                    pem_type = line[11:line.index('-',11)]
                    state = 'read'
            elif state == 'read':
                if line[:9] == '-----END ':
                    state = 'found'
                    break
                b64 += line.strip()
        if state != 'found':
            raise ValueError('PEM format error')
        print(f'[{pem_type}]')
        return base64.b64decode(b64)

#>    @staticmethod
#>    def parse(text: str) -> bytes:
    

OBJECT_IDENTIFIERS = {
    '1.2.840.113549.1.1.1': 'X509 RSA',
}
