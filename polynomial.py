#!/usr/bin/python3

from functools import total_ordering

@total_ordering
def Polynomial(p: int|list[int]):
    class _P:
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

        def __mul__(self, rhs):
            value1 = self.value
            value2 = rhs.value
            result = 0
            mask = self.mask
            p = self.p
            while value2:
                if value2 & 1:
                    result ^= value1
                value1 <<= 1
                if value1 & mask > 0:
                    value1 ^= p
                value2 >>= 1
            return _P(result)

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
            mask = self.mask
            p = self.p
            while value2:
                if value2 & 1:
                    result = result * value1
                value1 = value1 * value1
                value2 >>= 1
            return result

    if isinstance(p, list):
        mask = 1<<max(p)
        p = sum(1<<n for n in p)
    else:
        m = 0
        p2 = p>>1
        while p2:
            m += 1
            p2 >>= 1
    _P.p = p
    _P.mask = mask
    return _P
