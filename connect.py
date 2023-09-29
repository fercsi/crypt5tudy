#!/usr/bin/python3

import sys
import tls
import ecdh
import hashlib
import socket
#>import random

#>h = hashlib.sha384(b'ABC')
#>print(h.hexdigest())
#>r = Handshake()

def mkClientHello():
    r = tls.ClientHello(['TLS_AES_128_GCM_SHA256'])
    e = tls.ServerName("www.fercsi.com")
    r.addExtension(e)
    e = tls.SupportedGroups(['x25519'])
    r.addExtension(e)
    e = tls.SignatureAlgorithms(['RSA-PSS-RSAE-SHA256'])
    r.addExtension(e)
    e = tls.SupportedVersions(['tls1.3'])
    r.addExtension(e)
    e = tls.PskKeyExchangeModes(['psk_dhe_ke'])
    r.addExtension(e)
    priv, pub = ecdh.generateKeyPairX25519()
    e = tls.KeyShare(pub, 'x25519')
    r.addExtension(e)

    return r.pack()

def sendPacket(packet):
    HOST = "127.0.0.1"
    PORT = 443

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(packet)
        response = s.recv(65536)

    return response

packet = mkClientHello()
response = sendPacket(packet)
serverHello = tls.unpackRecord(response)
print(serverHello)

#>print(''.join(f'{b:0>2x}' for b in bs))
#>sys.stdout.buffer.write(response)
#>bs = e.pack()
#>print(''.join(f'{b:0>2x}' for b in bs))
