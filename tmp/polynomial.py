#!/usr/bin/python3

class Modular:
    order: int
    def __init__(self, order):
        self.order = order

    def add(self, a: int, b: int):
        return (a + b) % self.order

    def mul(self, a: int, b: int):
        return (a * b) % self.order

class Polynomial(GFMethod):
    def __init__(self, order: int, generator: int):
        self.order = order
        self.generator = generator
        pass

class GaloisField:
    order: int
    method: GFMethod

    def __init__(self, order: int, *, method = '', generator = 0):
        self.order = order
        if method == '':
            if order & (order - 1) == 0:
                method = 'poly'
            else:
                method = 'mod'
        if method == 'poly':
            self.method = Polynomial(order, generator)
        else:
            self.method = Modular(order)

class GFValue:
    field: GaloisField
    value: int
    def __init__(self, field: GaloisField, value: int = 0):
        self.field = field
        self.value = value

    def set(self, value: int):
        self.value = value

    def __add__(self, oth):
        result = self.field.method.add(self.value, oth.value)
        return GFValue(self.field, result)

    def __mul__(self, oth):
        result = self.field.method.mul(self.value, oth.value)
        return GFValue(self.field, result)

    def __str__(self):
        return str(self.value)


f = GaloisField(7)
v1 = GFValue(f, 5)
v2 = GFValue(f, 4)
v3 = GFValue(f, 3)
v = (v1 + v2) * v3
print(v1, v2, v3, v)
