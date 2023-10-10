#!/usr/bin/python3

import sys
import tls
import crypto

# ONLY AES-GCM is supported

def fail(message: str|None = None):
    if message:
        print(message, file=sys.stderr)
    print(f'Usage: {sys.argv[0]} RECORDFILE [KEY NONE [RECORDSN]]', file=sys.stderr)
    sys.exit()

def decrypt_record(record_text: bytes) -> bytes:
    global key, nonce, recsn
    gcm = crypto.GCM(crypto.AES(key))
    auth_data = record_text[:5]
    cipher_text = record_text[5:-16] # 16 bytes for GCM
    auth_tag_expected = record_text[-16:]
    iv = (nonce ^ recsn).to_bytes(12, 'big')
    plain_text, auth_tag = gcm.decrypt(cipher_text, auth_data, iv)
    if auth_tag != auth_tag_expected:
        fail('Wrong parameter (key, nonce, or recordSN), or record does not use AES-GCM for encryption')
    plain_record = plain_text[-1:] + b'\x03\x03' \
        + (len(plain_text) - 1).to_bytes(2, 'big') + plain_text[:-1]
    return plain_record

if len(sys.argv) == 1:
    fail()

fname = sys.argv[1]

key = None
nonce = None
if len(sys.argv) > 3:
    key = bytes.fromhex(sys.argv[2])
    nonce = int.from_bytes(bytes.fromhex(sys.argv[3]), 'big')
elif len(sys.argv) == 3:
    fail('Either give both the key and the nonce, or neither.')

recsn = 0
if len(sys.argv) > 4:
    recsn = int(sys.argv[4])

with open(fname,'rb') as f:
    content = f.read()
    records = tls.unpack_records(content)
    for record in records:
        if record.record_type == 23 and key is not None:
            decrypted = decrypt_record(record.raw_content)
            inner = tls.unpack_record(decrypted)
            print(f'[#]{inner}')
            recsn +=  1
            continue
        print(record)

