#!/usr/bin/python3
# RFC2313

import math
from typing import NamedTuple
from util.random import random_prime_with_bits, random_bytes

# derive from SEQUENCE aka RFC2313/7.
class RsaKey(NamedTuple):
    size: int # in bits
    n: int
    e: int


class RsaPrivateKey(NamedTuple):
    size: int # in bits
    n: int
    d: int
    e: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int


class Rsa:
    size: int
    default_e: int|None = 65537
    # Note: Public exponent is always 65537 by industry de facto standard. Don't
    # use a different one. 65537 is a Fermat prime (others: 3, 5, 17, 257).
    my_private_key: RsaPrivateKey | None
    peer_public_key: RsaKey | None
    mode: int = 0

    def __init__(self, size: int = 2048) -> None:
        self.size = size

    def generate_key_pair(self) -> None:
        """Generate RSA key pairs

        This is a very naive key generation method. Please, do not use it in
        real applications. Generating reliable (non-breakable) keys which are
        also efficient to use is a significantly more complex task. Some issues:

        - primes might be too close to each other
        - (p-1) and (q-1) might have lots of common divisors
        - (p-1) or (q-1) might have only small prime factors
        - etc.

        The only aspect taken into account was, that they work properly.
        """
        # Note: 2 leading ones in primes, so that the multiplication is of the
        # expected number of bits.
        psize = self.size >> 1
        qsize = self.size - psize
        e = self.default_e
        if e is not None:
            p = e + 1
            q = p
            while math.gcd(p - 1, e) != 1:
                p = random_prime_with_bits(psize, leading_ones=2)
            while math.gcd(q - 1, e) != 1:
                q = random_prime_with_bits(qsize, leading_ones=2)
        else:
            p = random_prime_with_bits(psize, leading_ones=2)
            q = random_prime_with_bits(qsize, leading_ones=2)
        self.generate_rsa_parameters(p, q, e)

    def generate_rsa_parameters(self, p: int, q: int, e: int|None = None):
        if e is None:
            e = self.default_e
        n = p * q
        # TODO: use Carmichael algorithm?
        phi = (p - 1) * (q - 1) # Euler's totient function
        if e is None:
            e = 3 # (prime-1) is always divisible by 2
            while math.gcd(phi, e) != 1:
                e += 1
        d = pow(e, -1, phi) # modular inverse
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = pow(q, -1, p)
        size = n.bit_length() + 7 & ~7
        self.my_private_key = RsaPrivateKey(
            size=size, n=n, p=p, q=q, e=e, d=d, dp=dp, dq=dq, qinv=qinv
            )

    def get_my_public_key(self) -> RsaKey:
        pk = self.my_private_key
        return RsaKey(n=pk.n, e=pk.e, size=pk.size)

    def set_peer_public_key(self, exponent: int|RsaKey, modulus: int|None = None):
        if isinstance(exponent, RsaKey):
            self.peer_public_key = exponent
        else:
            size = modulus.bit_length() + 7 & ~7
            self.peer_public_key = RsaKey(size=size, n=modulus, e=exponent)

    def encrypt(self, message: bytes):
        pubk = self.peer_public_key
        e, n, size = pubk.e, pubk.n, pubk.size >> 3
        msg = int.from_bytes(message, 'big')
        cph = pow(msg, e, n)
        cipherMessage = cph.to_bytes(size, 'big')
        return cipherMessage

    def decrypt(self, cipherMessage: bytes):
        pk = self.my_private_key
        d, n = pk.d, pk.n
        cph = int.from_bytes(cipherMessage, 'big')
        msg = pow(cph, d, n)
        size = msg.bit_length() + 7 >> 3
        message = msg.to_bytes(size, 'big')
        return message

    def _encrypt(self, block_type: int, key: RsaPrivateKey|RsaKey, data: bytes):
        # RFC2313/8
        e, n, k = key.e, key.n, key.k >> 3
        data_length = len(data)
        if block_type == 0:
            # 00 || 00 || 00 || D
            max_size = (k >> 3) - 3
            if data_length > max_size:
                raise ValueError("Message too long, cannot be encrypted")
            encryption_block = data
        else: # block type 1(private key) or 2(public key)
            # 00 || BT || PS || 00 || D
            # len(PS) >= 8
            max_size = (k >> 3) - 11
            if data_length > max_size:
                raise ValueError("Message too long, cannot be encrypted")
            ps_size = k - data_length - 3
            ps = random_bytes(ps_size)
            encryption_block = bytes([block_type]) + ps + b'\0' + data

        x = int.from_bytes(encryption_block, 'big')
        y = pow(x, e, n)
        encrypted_data = y.to_bytes(k, 'big')
        return encrypted_data

    def _decrypt(self, key: RsaPrivateKey|RsaKey, cipherMessage: bytes):
        n = key.n
        if isinstance(key, RsaPrivateKey):
            c = key.d
        else:
            c = key.e
        cph = int.from_bytes(cipherMessage, 'big')
        msg = pow(cph, c, n)
        size = msg.bit_length() + 7 >> 3
        block_type = 0
        message = msg.to_bytes(size, 'big')
        if size == (key.size >> 3) - 1: # block_type
            block_type = message[0]
            message = message[message.index(b'\0')+1:]
        return message


