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

def mkClientHello():
    global priv, pub, clientHello
#>    r = tls.ClientHello(['TLS_AES_256_GCM_SHA384'])
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

    clientHello = r.pack()
    return clientHello

def sendPacket(packet):
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

def getKeys(crs, sharedSecret):
    global clientHello, serverHello
    global clientHandshakeTrafficSecret , serverHandshakeTrafficSecret
    global handshakeSecret
    hkdf = crs.hkdf
    earlySecret = hkdf.extract(None, None)

    derivedSecret = hkdf.deriveSecret(earlySecret, "derived", [])
    handshakeSecret = hkdf.extract(derivedSecret, sharedSecret)
#>    print(handshakeSecret.hex())

    clientHandshakeTrafficSecret = hkdf.deriveSecret(handshakeSecret, "c hs traffic", [clientHello[5:], serverHello[5:]])
#>    print(clientHandshakeTrafficSecret.hex())
    serverHandshakeTrafficSecret = hkdf.deriveSecret(handshakeSecret, "s hs traffic", [clientHello[5:], serverHello[5:]])
#>    print(serverHandshakeTrafficSecret.hex())

    derivedSecret = hkdf.deriveSecret(handshakeSecret, "derived", [])
    masterSecret = hkdf.extract(derivedSecret, None)
#>    print(masterSecret.hex())

    clientWriteKey = hkdf.expandLabel(clientHandshakeTrafficSecret, 'key', b'', crs.keyLength)
#>    print(clientWriteKey.hex())
    clientWriteIv = hkdf.expandLabel(clientHandshakeTrafficSecret, 'iv', b'', 12)
#>    print(clientWriteIv.hex())

    serverWriteKey = hkdf.expandLabel(serverHandshakeTrafficSecret, 'key', b'', crs.keyLength)
#>    print(serverWriteKey.hex())
    serverWriteIv = hkdf.expandLabel(serverHandshakeTrafficSecret, 'iv', b'', 12)
#>    print(serverWriteIv.hex())

    return clientWriteKey, clientWriteIv, serverWriteKey, serverWriteIv

def getApKeys(crs, handshakeTotal):
#>    global clientHello, serverHello
#>    global clientHandshakeTrafficSecret , serverHandshakeTrafficSecret
    global handshakeSecret
    hkdf = crs.hkdf

    derivedSecret = hkdf.deriveSecret(handshakeSecret, "derived", [])
    masterSecret = hkdf.extract(derivedSecret, None)
#>    print(handshakeSecret.hex())

    clientApplicationTrafficSecret = hkdf.deriveSecret(masterSecret, "c ap traffic", handshakeTotal)
#>    print(clientApplicationTrafficSecret.hex())
    serverApplicationTrafficSecret = hkdf.deriveSecret(masterSecret, "s ap traffic", handshakeTotal)
#>    print(serverApplicationTrafficSecret.hex())

    clientWriteKey = hkdf.expandLabel(clientApplicationTrafficSecret, 'key', b'', crs.keyLength)
#>    print(clientWriteKey.hex())
    clientWriteIv = hkdf.expandLabel(clientApplicationTrafficSecret, 'iv', b'', 12)
#>    print(clientWriteIv.hex())

    serverWriteKey = hkdf.expandLabel(serverApplicationTrafficSecret, 'key', b'', crs.keyLength)
#>    print(serverWriteKey.hex())
    serverWriteIv = hkdf.expandLabel(serverApplicationTrafficSecret, 'iv', b'', 12)
#>    print(serverWriteIv.hex())

    return clientWriteKey, clientWriteIv, serverWriteKey, serverWriteIv

# Real connect
#>packet = mkClientHello()
#>response = sendPacket(packet)

# Read data
with open('tmp/xargs_clienthello.bin', 'rb') as f:
    clientHello = f.read()
with open('tmp/xargs_response.bin', 'rb') as f:
    response = f.read()
priv=bytes.fromhex('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
pub=bytes.fromhex('358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254')


print('>', clientHello[5:].hex())
print(tls.unpackRecord(clientHello))
#>serverHello = tls.unpackRecord(response)
#>print(serverHello)
records = tls.unpackRecords(response)
serverHello = records[0].rawContent
print('>', serverHello[5:].hex())
peerPubKey = records[0].extensions[1].keys[0].key
crs = crypto.CryptoSuite(records[0].cipherSuite)
sharedSecret = ecdh.createSecret(priv, peerPubKey)
#>print(priv.hex())
#>print(pub.hex())
cKey, cIV, sKey, sIV = getKeys(crs, sharedSecret)
crs.setMyKey(cKey)
crs.setPeerKey(sKey)
crs.setMyNonce(cIV)
crs.setPeerNonce(sIV)
handshakeSofar = [clientHello[5:], serverHello[5:]]
for r in records:
    if r.recordType == 23:
        plainText, authTag = crs.aead.decrypt(r.cipherText, r.authData)
        if r.authTag != authTag:
            sys.exit(1)
        rhead = plainText[-1:] + r.rawContent[1:3] \
                + (int.from_bytes(r.rawContent[3:5], 'big') - 17).to_bytes(2, 'big')
        rbody = plainText[:-1]
        r2 = tls.unpackRecord(rhead+rbody)
        print(f'*{r2}')
        if r2.handshakeType == 20: #Finished
            hkdf = crs.hkdf
            finishedKey = hkdf.expandLabel(serverHandshakeTrafficSecret , "finished", b'', crs.hashLength)
#>            print(finishedKey.hex())
#>            for hs in handshakeSofar:
#>                print('...', hs.hex())
            tomac = crs.hashFunction(b''.join(handshakeSofar)).digest()
            verifyData = hkdf.hmacHash(finishedKey, tomac)
#>            verifyData = hkdf.hmacHash(finishedKey, b''.join(handshakeSofar))
            if r2.verifyData != verifyData:
                print('# Finishes.verify_data failed')

#>        print('>', rbody.hex())
        handshakeSofar.append(rbody)
        if r2.handshakeType == 20: #Finished
            cKey, cIV, sKey, sIV = getApKeys(crs, handshakeSofar)
    else:
        print(r)

##### CLIENT ANSWER #####

# Change cipherspec
client2 = tls.ChangeCipherSpec().pack()

hkdf = crs.hkdf
finishedKey = hkdf.expandLabel(clientHandshakeTrafficSecret , "finished", b'', crs.hashLength)
#>print(finishedKey.hex())
#>for hs in handshakeSofar:
#>    print('...', hs.hex())
tomac = crs.hashFunction(b''.join(handshakeSofar)).digest()
verifyData = hkdf.hmacHash(finishedKey, tomac)
packed = tls.Finished(verifyData).pack()
plainText = packed[5:] + packed[:1]
# TODO "+ 16" should change with AEAD. In case of GCM it is always 16
authData = b'\x17\x03\x03' + (len(plainText) + 16).to_bytes(2, 'big')
cipherText, authTag = crs.aead.encrypt(plainText, authData)
data = cipherText + authTag
client2 += tls.ApplicationData(data).pack()

## HANDSHAKE FINISHED FROM BOTH SIDE

crs.setMyKey(cKey)
crs.setPeerKey(sKey)
crs.setMyNonce(cIV)
crs.setPeerNonce(sIV)

plainText = b'ping\x17'
authData = b'\x17\x03\x03' + (len(plainText) + 16).to_bytes(2, 'big')
cipherText, authTag = crs.aead.encrypt(plainText, authData)
data = cipherText + authTag

client2 += tls.ApplicationData(data).pack()
print(client2.hex())


#>print(''.join(f'{b:0>2x}' for b in bs))
#>sys.stdout.buffer.write(response)
#>bs = e.pack()
#>print(''.join(f'{b:0>2x}' for b in bs))
