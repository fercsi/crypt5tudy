#!/usr/bin/python3
# https://www.openssh.com/specs.html
# https://coolaj86.com/articles/the-openssh-private-key-format/
# https://github.com/openssh/openssh-portable/blob/master/sshkey.c
#   to find th 64 bit value

# Implemented features:
# - read OpenSSH keys (rsa, ecdsa, ed25519)

from util.serialize import *
from util.pem import Pem


class OpenSshKey:
    def __init__(self, fname):
        with open(fname, 'r') as f:
            pem_content = f.read()
        raw = Pem.parse(pem_content)[1]
        self.process(raw)

    def process(self, raw: bytes):
        if raw[:12] != b'openssh-key-':
            raise TypeError("object is not an OpenSSH Key")
        if raw[12:15] != b'v1\0':
            raise TypeError("Don't know how to handle this version of OpenSSH Key")
        pos = 15
        self.cipher_name, pos = _read_str(raw, pos)
        self.kdf_name, pos = _read_str(raw, pos)
        self.kdf, pos = _read_bytes(raw, pos)
        key_count =  unpack_u32(raw, pos)
        pos += 4
        assert key_count == 1
            # number of keys, hard-coded to 1
        raw_pubkey, pos = _read_bytes(raw, pos)
        raw_privkey, pos = _read_bytes(raw, pos)
        # eof

        key_type, pos = _read_str(raw_pubkey, 0)
        key_handler = _KEY_HANDLERS.get(key_type, None)
        if key_handler is None:
            raise NotImplementedError(f"Key type '{key_type}' is currently not supported")
        self.public_key = key_handler.deserialize_sshpub(raw_pubkey)
        # Todo: decrypt if password protected: AES256-CTR +bcrypt kdf
#>        chk1 = raw_privkey[:4] # if passphrase is good, the two random values match
#>        chk2 = raw_privkey[4:8]
#>        if chk1 != chk2:
#>            raise ValueError("Wrong passphrase")
        self.private_key = key_handler.deserialize_sshpriv(raw_privkey[8:])


# ---- Key handlers ----
class SshKey:
    key_type: str
    def __init__(self, key_type: str, **kwargs):
        self.key_type = key_type
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __str__(self) -> str:
        values = [f'{k}={v!r}' for k, v in self.to_dict().items()]
        return type(self).__name__ + '(' + ', '.join(values) + ')'

    def to_dict(self) -> dict:
        params = {k: getattr(self, k) for k in dir(self) if k[0] != '_'}
        return {k: v for k, v in params.items() if not callable(v)}


class SshRsaKeyHandler:
    def deserialize_sshpub(raw: bytes) -> SshKey:
        pos = 0
        key_type, pos = _read_str(raw, pos)
        e, pos = _read_sint(raw, pos)
        n, pos = _read_sint(raw, pos)
        return SshKey(key_type, e=e, n=n)

    def deserialize_sshpriv(raw: bytes) -> SshKey:
        pos = 0
        key_type, pos = _read_str(raw, pos)
        n, pos = _read_sint(raw, pos)
        e, pos = _read_sint(raw, pos)
        d, pos = _read_sint(raw, pos)
        qinv, pos = _read_sint(raw, pos)
        p, pos = _read_sint(raw, pos)
        q, pos = _read_sint(raw, pos)
        comment, pos = _read_str(raw, pos)
        return SshKey(key_type, n=n, e=e, d=d, qinv=qinv, p=p, q=q, comment=comment)


class SshEcdsaKeyHandler:
    def deserialize_sshpub(raw: bytes) -> SshKey:
        pos = 0
        key_type, pos = _read_str(raw, pos)
        sub_type, pos = _read_str(raw, pos)
        pub, pos = _read_bytes(raw, pos)
        assert pub[0] == 4 # standard
        size = len(pub) >> 1
        x = unpack_sint(pub, 1, size)
        y = unpack_sint(pub, size + 11, size)
        return SshKey(key_type, sub_type=sub_type, x=x, y=y)

    def deserialize_sshpriv(raw: bytes) -> SshKey:
        pos = 0
        key_type, pos = _read_str(raw, pos)
        sub_type, pos = _read_str(raw, pos)
        pub, pos = _read_bytes(raw, pos)
        assert pub[0] == 4 # standard
        size = len(pub) >> 1
        x = unpack_sint(pub, 1, size)
        y = unpack_sint(pub, size + 11, size)
        priv, pos = _read_sint(raw, pos)
        comment, pos = _read_str(raw, pos)
        return SshKey(key_type, sub_type=sub_type, x=x, y=y, priv=priv, comment=comment)
        print(raw[pos:].hex())
        import sys
        sys.exit()
        pub, pos = _read_sint(raw, pos)
        priv, pos = _read_sint(raw, pos)
        return SshKey(key_type, pub=pub, priv=priv, comment=comment)


class SshEd25519KeyHandler:
    def deserialize_sshpub(raw: bytes) -> SshKey:
        pos = 0
        key_type, pos = _read_str(raw, pos)
        pub, pos = _read_sint(raw, pos)
        return SshKey(key_type, pub=pub)

    def deserialize_sshpriv(raw: bytes) -> SshKey:
        pos = 0
        key_type, pos = _read_str(raw, pos)
        pub, pos = _read_sint(raw, pos)
        priv, pos = _read_sint(raw, pos)
        comment, pos = _read_str(raw, pos)
        return SshKey(key_type, pub=pub, priv=priv, comment=comment)


_KEY_HANDLERS = {
    'ssh-rsa': SshRsaKeyHandler,
    'ecdsa-sha2-nistp256': SshEcdsaKeyHandler,
    'ecdsa-sha2-nistp384': SshEcdsaKeyHandler,
    'ecdsa-sha2-nistp521': SshEcdsaKeyHandler,
    'ssh-ed25519': SshEd25519KeyHandler,
}


def _read_sint(raw, pos):
    l = unpack_u32(raw, pos)
    pos += 4
    value = unpack_sint(raw[pos:pos+l])
    pos += l
    return value, pos

def _read_str(raw, pos):
    l = unpack_u32(raw, pos)
    pos += 4
    value = raw[pos:pos+l].decode()
    pos += l
    return value, pos

def _read_bytes(raw, pos):
    l = unpack_u32(raw, pos)
    pos += 4
    value = raw[pos:pos+l]
    pos += l
    return value, pos
