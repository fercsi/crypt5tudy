#!/usr/bin/python3
# https://coolaj86.com/articles/the-openssh-private-key-format/
# https://github.com/openssh/openssh-portable/blob/master/sshkey.c
#   to find th 64 bit value

from typing import NamedTuple
from util.serialize import *

class OpenSSHPublicKey(NamedTuple):
    keytype: str
    pub0: int
    pub1: int

class OpenSshKey:
    def process(self, raw: bytes):
        if raw[:12] != b'openssh-key-':
            raise TypeError("object is not an OpenSSH Key")
        if raw[12:15] != b'v1\0':
            raise TypeError("Don't know how to handle this version of OpenSSH Key")
        pos = 15
        l = unpack_u32(raw, pos)
        pos += 4
        self.ciphername = raw[pos:pos+l].decode()
        pos += l
        l = unpack_u32(raw, pos)
        pos += 4
        self.kdfname = raw[pos:pos+l].decode()
        pos += l
        l = unpack_u32(raw, pos)
        pos += 4
        self.kdf = raw[pos:pos+l]
        pos += l
        assert unpack_u32(raw, pos) == 1 # number of keys, hard-coded to 1
        pos += 4
        
        # Public Key RFC4253
        l = unpack_u32(raw, pos) # length og public key, not necessary at this point
        pos += 4
        l = unpack_u32(raw, pos)
        pos += 4
        keytype = raw[pos:pos+l].decode()
        pos += l
        l = unpack_u32(raw, pos)
        pos += 4
        pub0 = unpack_uint(raw[pos:pos+l])
        pos += l
        l = unpack_u32(raw, pos)
        pos += 4
        pub1 = unpack_uint(raw[pos:pos+l])
        pos += l
        self.sshpub = OpenSSHPublicKey(keytype, pub0, pub1)

        # Private key

# ecdsa-sha2-nistp256-cert-v01@openssh.com,
# ecdsa-sha2-nistp384-cert-v01@openssh.com,
# ecdsa-sha2-nistp521-cert-v01@openssh.com,
# ssh-ed25519-cert-v01@openssh.com,
# rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,
# ssh-rsa-cert-v01@openssh.com,
# ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,
# ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa
