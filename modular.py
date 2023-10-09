#!/usr/bin/python3

from functools import total_ordering

@total_ordering
def Modular(p: int):
    class _M:
        p: int
        value: int
        def __init__(self, value):
            self.value = value

        def __int__(self) -> int:
            return self.value

        def __repr__(self) -> str:
            return repr(self.value)

        def __format__(self, fmt: str) -> str:
            return format(self.value, fmt)

        def __eq__(self, rhs) -> bool:
            if isinstance(rhs, _M):
                v = rhs.value
            else:
                v = rhs
            return self.value == v

        def __lt__(self, rhs) -> bool:
            if isinstance(rhs, _M):
                v = rhs.value
            else:
                v = rhs
            return self.value < v

        def __neg__(self):
            return _M((-self.value) % _M.p)

        def __add__(self, rhs):
            return _M((self.value + rhs.value) % _M.p)

        def __sub__(self, rhs):
            return _M((self.value - rhs.value) % _M.p)

        def __mul__(self, rhs):
            return _M(self.value * rhs.value % _M.p)

        def __rmul__(self, lhs: int):
            return _M(lhs * self.value % _M.p)

        def _inverse(self):
            return pow(self.value, -1, _M.p)

        def inverse(self):
            return _M(self._inverse())

        def __truediv__(self, rhs):
            return _M(self.value * rhs._inverse() % _M.p)

        def __rtruediv__(self, lhs: int):
            return _M(lhs * self._inverse() % _M.p)

        def __pow__(self, rhs: int):
            return _M(pow(self.value, rhs, _M.p))

        def sqrt(self):
            # ref: https://www.rieselprime.de/ziki/Modular_square_root
            if self.value == 0:
                return [_M(0)]
            m: int = self.p
            a = _M(self.value)
            x = a ** (m - 1 >> 1)
            if x != 1:
                return []
            if m % 4 == 3:
                c = a ** (m + 1 >> 2)
            elif m % 8 == 5:
                v = (2 * a) ** (m - 5 >> 3)
                i = 2 * a * v * v
                c = a * v * (i - _M(1))
            elif m % 8 == 1:
                # step 1:
                e: int = 0
                q: int = m - 1
                while (q & 1) == 0:
                    e += 1
                    q >>= 1
                # step 2:
                for x in range(2, m):
                    z = _M(x) ** q
                    t = z ** (1 << e - 1)
                    if t != 1:
                        break
                # step 3:
                y = z
                r: int = e
                x = a ** (q - 1 >> 1)
                v = a * x
                w = v * x
                # step 4:
                while w != 1:
                    # step 5:
                    k: int = 0
                    while w ** (1<<k) != 1:
                        k += 1
                    # step 6:
                    d = y ** (1 << r - k - 1)
                    y = d * d
                    r = k
                    v = d * v
                    w = w * y
                c = v
            return sorted([c, -c])
    _M.p = p
    return _M
