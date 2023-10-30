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
        return pem_type, base64.b64decode(b64)

    @staticmethod
    def create(pem_type: str, content: bytes) -> str:
        b64 = base64.b64encode(content).decode()
        text = f'-----BEGIN {pem_type}-----\n'
        text += '\n'.join(b64[i:i+64] for i in range(0, len(b64), 64)) + '\n'
        text += f'-----END {pem_type}-----\n'
        return text
