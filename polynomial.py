#!/usr/bin/python3

from functools import total_ordering

@total_ordering
def Polynomial(q: int|list[int], *, reverse = False):
    class _P:
        value: int
        degree: int
        reverse: bool
        q: int
        mask: int
        def __init__(self, value):
            self.value = value

        def __int__(self) -> int:
            return self.value

        def __repr__(self) -> str:
            return repr(self.value)

        def __format__(self, fmt: str) -> str:
            return format(self.value, fmt)

        def __eq__(self, rhs) -> bool:
            if isinstance(rhs, _P):
                v = rhs.value
            else:
                v = rhs
            return self.value == v

        def __lt__(self, rhs) -> bool:
            if isinstance(rhs, _P):
                v = rhs.value
            else:
                v = rhs
            return self.value < v

        def __neg__(self):
            return _P(self.value)

        def __add__(self, rhs):
            return _P(self.value ^ rhs.value)

        def __sub__(self, rhs):
            return _P(self.value ^ rhs.value)

        def _mul(self, rhs):
            value1 = self.value
            value2 = rhs.value
            result = 0
            mask = self.mask
            q = self.q
            while value2:
                if value2 & 1:
                    result ^= value1
                value1 <<= 1
                if value1 & mask:
                    value1 ^= q
                value2 >>= 1
            return _P(result)

        def _revmul(self, rhs):
            value1 = self.value
            value2 = rhs.value
            result = 0
            mask = self.mask
            chkmask = mask + 1 >> 1
            q = self.q
            while value2:
                if value2 & chkmask:
                    result ^= value1
                if value1 & 1:
                    value1 ^= q # degree+1 bits!
                value1 >>= 1
                value2 = (value2 << 1) & mask
            return _P(result)

        def __mul__(self, rhs):
            if self.reverse:
                return self._revmul(rhs)
            else:
                return self._mul(rhs)

        def __rmul__(self, lhs: int):
            return _P(lhs) * self

        def inverse(self):
            if (self.value == 0):
                raise ZeroDivisionError('division by zero')
            return self ** (self.mask - 2)

        def __truediv__(self, rhs):
            return self * rhs.inverse()

        def __rtruediv__(self, lhs: int):
            return _P(lhs) * self.inverse()

        def __pow__(self, rhs: int):
            if rhs == 0:
                # Note: following pythonic way, 0**0 = 1
                return _P(1)
            value1 = _P(self.value)
            value2 = rhs
            result = _P(1)
            while value2:
                if value2 & 1:
                    result = result * value1
                value1 = value1 * value1
                value2 >>= 1
            return result

        def __xor__(self, rhs):
            return _P(self.value ^ rhs.value)

    if isinstance(q, list):
        degree = max(q)
    else:
        degree = 0
        q2 = q>>1
        while q2:
            degree += 1
            q2 >>= 1

    if not reverse:
        mask = 1 << degree
        if isinstance(q, list):
            q = sum(1<<n for n in q)
    else:
        if isinstance(q, list):
            # note: degree+1 bits!
            q = sum(1<<(degree-n) for n in q)
            q ^= 1
        else:
            degree += 1
        mask = (1 << degree) - 1

    _P.q = q
    _P.degree = degree
    _P.mask = mask
    _P.reverse = reverse
    return _P
