#!/usr/bin/python3
# General form
# y^2 + a1*x*y + a3*y = x^3 + a2*x^2 + a4*x + a6
# Weierstrass form (secp*r1)
# y^2 = x^3 + ax + b 
# Montgomery form (25519, 448)
# y^2 = x^3 + A*x^2 + x

from typing import NamedTuple
from .modular import Modular

#>class ECPoint(NamedTuple):
#>    x: int
#>    y: int

def Weierstrass(*, a, b, p):
    # https://medium.com/asecuritysite-when-bob-met-alice/adding-points-in-elliptic-curve-cryptography-a1f0a1bce638
    class _EC:
        a: int
        b: int
        p: int
        x: int
        y: int

        def __init__(self, x: int|object, y: int|None = None):
            if isinstance(x, _EC):
                self.x = x.x
                self.y = x.y
            else:
                self.x = x
                self.y = y
                if self.y is None:
                    self.calculate_y()

        def calculate_y(self, x: int) -> None:
            M = Modular(_EC.p)
            x = M(self.x)
            y = M(self.y)
            a = M(self.a)
            b = M(self.b)
            z = x * x * x + a * x + b
            ys = z.sqrt()
            if len(ys) == 0:
                return # no y
            self.y = int(min(ys))

        def __add__(self, q):
            M = Modular(_EC.p)
            px = M(self.x)
            py = M(self.y)
            qx = M(q.x)
            qy = M(q.y)
            a = M(self.a)
            if px != qx:
                # slope is a line through P and Q
                s = (py - qy) / (px - qx)
            elif py == qy: # P == Q
                # slope is the tangent
                s = (3 * px * px + a) / (2 * py)
            else: # slope is vertical, sum is infinity
                return _EC(0, 0)

            x = s * s - qx - px
            y = s * (qx - x) - qy
            return _EC(int(x), int(y))

        def __rmul__(self, n: int):
            q = _EC(self)
            p = None
            while n:
                if n & 1:
                    if p is None:
                        p = _EC(q)
                    else:
                        p = p + q
                q = q + q
                n >>= 1
            return p

    _EC.a = a
    _EC.b = b
    _EC.p = p
    bits = 0
    while p:
        p >>= 1
        bits += 1
    _EC.bits = bits
    return _EC

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
