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
r.add_extension(e)
#>e = tls.EcPointFormats(['uncompressed'])
#>r.add_extension(e)
e = tls.SupportedGroups(['x25519'])
r.add_extension(e)
#>r.add_extension(tls.SessionTicket())
#>r.add_extension(tls.ExtendedMasterSecret())
e = tls.SignatureAlgorithms(['RSA-PSS-RSAE-SHA256'])
r.add_extension(e)
e = tls.SupportedVersions(['tls1.3'])
r.add_extension(e)
e = tls.PskKeyExchangeModes(['psk_dhe_ke'])
r.add_extension(e)
priv, pub = ecdh.generate_key_pairX25519()
e = tls.KeyShare(pub, 'x25519')
r.add_extension(e)
bs = r.pack()
#>print(''.join(f'{b:0>2x}' for b in bs))
sys.stdout.buffer.write(bs)
#>bs = e.pack()
#>print(''.join(f'{b:0>2x}' for b in bs))
