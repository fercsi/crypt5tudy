#!/usr/bin/python3

import sys
import tls
import ecdh
import hashlib
import socket
import crypto
#>import random

#>h = hashlib.sha384(b'ABC')
#>print(h.hexdigest())
#>r = Handshake()

def mk_client_hello():
    global priv, pub, client_hello
#>    r = tls.ClientHello(['TLS_AES_256_GCM_SHA384'])
    r = tls.ClientHello(['TLS_AES_128_GCM_SHA256'])
    e = tls.ServerName("www.fercsi.com")
    r.add_extension(e)
    e = tls.SupportedGroups(['x25519'])
    r.add_extension(e)
    e = tls.SignatureAlgorithms(['RSA-PSS-RSAE-SHA256'])
    r.add_extension(e)
    e = tls.SupportedVersions(['tls1.3'])
    r.add_extension(e)
    e = tls.PskKeyExchangeModes(['psk_dhe_ke'])
    r.add_extension(e)
    priv, pub = ecdh.generate_key_pairX25519()
    e = tls.KeyShare(pub, 'x25519')
    r.add_extension(e)

    client_hello = r.pack()
    return client_hello

def send_packet(packet):
    HOST = "127.0.0.1"
    PORT = 443

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(packet)
        response = s.recv(65536)
        while True:
            pos = 3
            while pos < len(response):
                l = int.from_bytes(response[pos:pos+2])
#>                print(l)
                pos += l + 5
#>            print(pos, len(response))
            if pos-3 == len(response):
                break
            response += s.recv(65536)

    return response

def get_keys(crs, shared_secret):
    global client_hello, server_hello
    global client_handshake_traffic_secret , server_handshake_traffic_secret
    global handshake_secret
    hkdf = crs.hkdf
    early_secret = hkdf.extract(None, None)

    derived_secret = hkdf.derive_secret(early_secret, "derived", [])
    handshake_secret = hkdf.extract(derived_secret, shared_secret)
#>    print(handshake_secret.hex())

    client_handshake_traffic_secret = hkdf.derive_secret(handshake_secret, "c hs traffic", [client_hello[5:], server_hello[5:]])
#>    print(client_handshake_traffic_secret.hex())
    server_handshake_traffic_secret = hkdf.derive_secret(handshake_secret, "s hs traffic", [client_hello[5:], server_hello[5:]])
#>    print(server_handshake_traffic_secret.hex())

    derived_secret = hkdf.derive_secret(handshake_secret, "derived", [])
    master_secret = hkdf.extract(derived_secret, None)
#>    print(master_secret.hex())

    client_write_key = hkdf.expand_label(client_handshake_traffic_secret, 'key', b'', crs.key_length)
#>    print(client_write_key.hex())
    client_write_iv = hkdf.expand_label(client_handshake_traffic_secret, 'iv', b'', 12)
#>    print(client_write_iv.hex())

    server_write_key = hkdf.expand_label(server_handshake_traffic_secret, 'key', b'', crs.key_length)
#>    print(server_write_key.hex())
    server_write_iv = hkdf.expand_label(server_handshake_traffic_secret, 'iv', b'', 12)
#>    print(server_write_iv.hex())

    return client_write_key, client_write_iv, server_write_key, server_write_iv

def get_ap_keys(crs, handshake_total):
#>    global client_hello, server_hello
#>    global client_handshake_traffic_secret , server_handshake_traffic_secret
    global handshake_secret
    hkdf = crs.hkdf

    derived_secret = hkdf.derive_secret(handshake_secret, "derived", [])
    master_secret = hkdf.extract(derived_secret, None)
#>    print(handshake_secret.hex())

    client_application_traffic_secret = hkdf.derive_secret(master_secret, "c ap traffic", handshake_total)
#>    print(client_application_traffic_secret.hex())
    server_application_traffic_secret = hkdf.derive_secret(master_secret, "s ap traffic", handshake_total)
#>    print(server_application_traffic_secret.hex())

    client_write_key = hkdf.expand_label(client_application_traffic_secret, 'key', b'', crs.key_length)
#>    print(client_write_key.hex())
    client_write_iv = hkdf.expand_label(client_application_traffic_secret, 'iv', b'', 12)
#>    print(client_write_iv.hex())

    server_write_key = hkdf.expand_label(server_application_traffic_secret, 'key', b'', crs.key_length)
#>    print(server_write_key.hex())
    server_write_iv = hkdf.expand_label(server_application_traffic_secret, 'iv', b'', 12)
#>    print(server_write_iv.hex())

    return client_write_key, client_write_iv, server_write_key, server_write_iv

# Real connect
#>packet = mk_client_hello()
#>response = send_packet(packet)

# Read data
with open('tmp/xargs_clienthello.bin', 'rb') as f:
    client_hello = f.read()
with open('tmp/xargs_response.bin', 'rb') as f:
    response = f.read()
priv=bytes.fromhex('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
pub=bytes.fromhex('358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254')


print('>', client_hello[5:].hex())
print(tls.unpack_record(client_hello))
#>server_hello = tls.unpack_record(response)
#>print(server_hello)
records = tls.unpack_records(response)
server_hello = records[0].raw_content
print('>', server_hello[5:].hex())
peer_pub_key = records[0].extensions[1].keys[0].key
crs = crypto.CryptoSuite(records[0].cipher_suite)
shared_secret = ecdh.create_secret(priv, peer_pub_key)
#>print(priv.hex())
#>print(pub.hex())
c_key, cIV, s_key, sIV = get_keys(crs, shared_secret)
crs.set_my_key(c_key)
crs.set_peer_key(s_key)
crs.set_my_nonce(cIV)
crs.set_peer_nonce(sIV)
handshake_sofar = [client_hello[5:], server_hello[5:]]
for r in records:
    if r.record_type == 23:
        plain_text, auth_tag = crs.aead.decrypt(r.cipher_text, r.auth_data)
        if r.auth_tag != auth_tag:
            sys.exit(1)
        rhead = plain_text[-1:] + r.raw_content[1:3] \
                + (int.from_bytes(r.raw_content[3:5], 'big') - 17).to_bytes(2, 'big')
        rbody = plain_text[:-1]
        r2 = tls.unpack_record(rhead+rbody)
        print(f'*{r2}')
        if r2.handshake_type == 20: #Finished
            hkdf = crs.hkdf
            finished_key = hkdf.expand_label(server_handshake_traffic_secret , "finished", b'', crs.hash_length)
#>            print(finished_key.hex())
#>            for hs in handshake_sofar:
#>                print('...', hs.hex())
            tomac = crs.hash_function(b''.join(handshake_sofar)).digest()
            verify_data = hkdf.hmac_hash(finished_key, tomac)
#>            verify_data = hkdf.hmac_hash(finished_key, b''.join(handshake_sofar))
            if r2.verify_data != verify_data:
                print('# Finishes.verify_data failed')

#>        print('>', rbody.hex())
        handshake_sofar.append(rbody)
        if r2.handshake_type == 20: #Finished
            c_key, cIV, s_key, sIV = get_ap_keys(crs, handshake_sofar)
    else:
        print(r)

##### CLIENT ANSWER #####

# Change cipherspec
client2 = tls.ChangeCipherSpec().pack()

hkdf = crs.hkdf
finished_key = hkdf.expand_label(client_handshake_traffic_secret , "finished", b'', crs.hash_length)
#>print(finished_key.hex())
#>for hs in handshake_sofar:
#>    print('...', hs.hex())
tomac = crs.hash_function(b''.join(handshake_sofar)).digest()
verify_data = hkdf.hmac_hash(finished_key, tomac)
packed = tls.Finished(verify_data).pack()
plain_text = packed[5:] + packed[:1]
# TODO "+ 16" should change with AEAD. In case of GCM it is always 16
auth_data = b'\x17\x03\x03' + (len(plain_text) + 16).to_bytes(2, 'big')
cipher_text, auth_tag = crs.aead.encrypt(plain_text, auth_data)
data = cipher_text + auth_tag
client2 += tls.ApplicationData(data).pack()

## HANDSHAKE FINISHED FROM BOTH SIDE

crs.set_my_key(c_key)
crs.set_peer_key(s_key)
crs.set_my_nonce(cIV)
crs.set_peer_nonce(sIV)

plain_text = b'ping\x17'
auth_data = b'\x17\x03\x03' + (len(plain_text) + 16).to_bytes(2, 'big')
cipher_text, auth_tag = crs.aead.encrypt(plain_text, auth_data)
data = cipher_text + auth_tag

client2 += tls.ApplicationData(data).pack()
print(client2.hex())


#>print(''.join(f'{b:0>2x}' for b in bs))
#>sys.stdout.buffer.write(response)
#>bs = e.pack()
#>print(''.join(f'{b:0>2x}' for b in bs))
