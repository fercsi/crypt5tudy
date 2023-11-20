#!/usr/bin/python3
# Note: for larger random numbers we use pseudo random generator with true
# random feed

from secrets import randbits, token_bytes
from random import seed, randint, randrange

def random_bytes(size: int) -> bytes:
    """Create a (true) random byte string of `size` bytes
    """
    return token_bytes(size)

def random_int_with_bits(size: int, *, leading_ones: int = 0) -> int:
    """Create a random integer with given bit size

    **IMPORTANT NOTE**: This function uses OS pseudo-random generator'

    Parameters
    ----------
    size : int
        Number of bits in random integer
    leading_ones : int, optional, default is 0
        Number of fix ones at MSB of the integer. If you want to guarantee the
        bit size of the integer, set 1 to this value. Similarly, if you want to
        guarantee the bit size of the multiplication of two random values
        (mainly primes), using 2 is the proper choice.
    """
    lead = (1 << leading_ones) - 1
    low = lead << size - leading_ones
    high = 1 << size
    return randrange(low, high)

def random_prime_with_bits(size: int, *, leading_ones: int = 1) -> int:
    """Create a random prime with given bit size

    For more information, see `random_int_with_bits`.

    _Note, that default value of `leading_ones` is 1_
    """
    # seed is true random. Seed size must be the same size as the result, but it
    # is sufficient to continue with several pseudo-random guesses
    seed(randbits(size))
    # further steps are pseudo random
    while True:
        prime = _get_prime_candidate(size, leading_ones)
        if _check_millerrabin(prime):
            return prime

# ---- Non-public content ----

_PRIME_LIST = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499
    ]

def _get_prime_candidate(size: int, leading_ones: int) -> int:
    while True:
        prime = random_int_with_bits(size, leading_ones=leading_ones)
        for div in _PRIME_LIST:
            if prime % div == 0:
                break
        else:
            return prime

def _check_millerrabin(n: int) -> bool:
    k = 64
    d = n - 1
    s = 0
    while (d & 1) == 0:
        s = s + 1
        d = d >> 1

    for _ in range(k):
        a = randint(2, n - 2)
        x = pow(a, d, n)
        for __ in range(s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n - 1:
                # nontrivial square root of 1 modulo n
                return False
            x = y
        if y != 1:
            return False
    return True
