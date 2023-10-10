#!/usr/bin/python3

from typing import NamedTuple
from modular import Modular

class ECPoint(NamedTuple):
    x: int
    y: int

class Weierstrass:
    # https://medium.com/asecuritysite-when-bob-met-alice/adding-points-in-elliptic-curve-cryptography-a1f0a1bce638
    def __init__(self, order, a, b):
        self.order = order
        self.a = a
        self.b = b

    def x_to_point(self, x: int) -> ECPoint:
        z = (x * x * x + self.a * x + self.b) % self.order
        m = Modular(self.order)
        ys = m.sqrt(z)
        if len(ys) == 0:
            return None
        return ECPoint(x, min(ys))

    def add(self, p: ECPoint, q: ECPoint) -> ECPoint:
        m = Modular(self.order)
        s = m.div(p.y - q.y, p.x - q.x)
        x = (s * s - q.x - p.x) % self.order
        y = (s * (q.x - x) - q.y) % self.order
        return ECPoint(x, y)

    def mul(self, n: int, p: ECPoint) -> ECPoint:
        q = p
        p = None
        while n:
            if n & 1:
                if p is None:
                    p = q
                else:
                    p = self.add(p, q)
            q = self.add(q, q)
            n >>= 1
        return p

def Montgomery(*, A, p, bits):
    # by^2 = x^3 + ax^2 + x
    class _EC:
        A: int
        B: int
        p: int
        bits: int
        u: int
        def __init__(self, u: int):
            self.u = u

        def __int__(self) -> int:
            return self.u

        def __rmul__(self, k: int):
            a24 = (_EC.A - 2) >> 2

            M = Modular(_EC.p)
            x_1 = M(self.u)
            x_2 = M(1)
            z_2 = M(0)
            x_3 = M(self.u)
            z_3 = M(1)
            swap = 0

            for t in range(_EC.bits-1, -1, -1):
                k_t = (k >> t) & 1
                swap ^= k_t
                (x_2, x_3) = cswap(swap, x_2, x_3)
                (z_2, z_3) = cswap(swap, z_2, z_3)
                swap = k_t

                A = x_2 + z_2
                AA = A ** 2
                B = x_2 - z_2
                BB = B ** 2
                E = AA - BB
                C = x_3 + z_3
                D = x_3 - z_3
                DA = D * A
                CB = C * B
                x_3 = (DA + CB) ** 2
                z_3 = x_1 * (DA - CB) ** 2
                x_2 = AA * BB
                z_2 = E * (AA + a24 * E)

            x_2, x_3 = cswap(swap, x_2, x_3)
            z_2, z_3 = cswap(swap, z_2, z_3)
            u_2 = x_2 * z_2 ** (_EC.p - 2)
            return _EC(int(u_2))

    def cswap(swap, x_2, x_3):
        # The cswap function SHOULD be implemented in constant time (i.e.,
        # independent of the swap argument). /RFC7748 5./
        tmp = (x_2, x_3, x_2)
        return tmp[swap:swap+2]

    _EC.A = A
    _EC.p = p
    _EC.bits = bits
    return _EC

EC25519 = Montgomery(A=486662, p=2**255 - 19, bits=255)
EC448 = Montgomery(A=156326, p=2**448 - 2**224 - 1, bits=448)
