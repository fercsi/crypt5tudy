#!/usr/bin/python3

import sys
import tls
import ecdh
import hashlib
#>import random

#>h = hashlib.sha384(b'ABC')
#>print(h.hexdigest())
#>r = Handshake()
r = tls.ClientHello(['TLS_AES_128_GCM_SHA256'])
e = tls.ServerName("www.fercsi.com")
r.addExtension(e)
#>e = tls.EcPointFormats(['uncompressed'])
#>r.addExtension(e)
e = tls.SupportedGroups(['x25519'])
r.addExtension(e)
#>r.addExtension(tls.SessionTicket())
#>r.addExtension(tls.ExtendedMasterSecret())
e = tls.SignatureAlgorithms(['RSA-PSS-RSAE-SHA256'])
r.addExtension(e)
e = tls.SupportedVersions(['tls1.3'])
r.addExtension(e)
e = tls.PskKeyExchangeModes(['psk_dhe_ke'])
r.addExtension(e)
priv, pub = ecdh.generateKeyPairX25519()
e = tls.KeyShare(pub, 'x25519')
r.addExtension(e)
bs = r.pack()
#>print(''.join(f'{b:0>2x}' for b in bs))
sys.stdout.buffer.write(bs)
#>bs = e.pack()
#>print(''.join(f'{b:0>2x}' for b in bs))
