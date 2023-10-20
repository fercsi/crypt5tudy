#!/usr/bin/python3

from abc import ABC, ABCMeta, abstractmethod

class MetaHashFunction(ABCMeta):
    def __new__(metacls, cls, bases, classdict, **kwargs):
#>        print('-'*40)
#>        print(cls)
#>        print(bases)
#>        print(metacls._check_inheritance(bases))
#>        metacls._check_mandatory_field(cls, bases, 'init')
        try:
            digest_size = classdict['digest_size']
        except:
            raise KeyError('digest_size is missing')
        classdict['name'] = property(lambda _: cls)
        classdict['digest_size'] = property(lambda _: digest_size)

#>        try:
#>            init = classdict['init']
#>            update = classdict['update']
#>            final = classdict['digest']
#>        except:
#>            raise KeyError('methods init, update, final must be presented')
#>        del classdict['init']
#>        classdict['_init'] = init
        classdict['hexdigest'] = lambda self: self.digest().hex()
        classdict['__init__'] = metacls.func_init
        classdict['_hash_function'] = True

        exc = None
        try:
            hash_func = super().__new__(metacls, cls, bases, classdict, **kwargs)
        except RuntimeError as e:
            exc = e.__cause__ or e
        if exc is not None:
            raise exc
        return hash_func

    def func_init(self, data: bytes|None = None):
        self.init()
        if data is not None:
            self.update(data)

    @classmethod
    def _check_inheritance(_, bases):
        for base in bases:
            if getattr(base, '_hash_function', False):
                return True
        return False

    @classmethod
    def _check_mandatory_field(_, cls, bases, field):
        for chain in bases:
            for base in chain.__mro__:
                print(vars(base))

class HashFunction(ABC, metaclass = MetaHashFunction):
    digest_size: int = 0

    @abstractmethod
    def init(self) -> None:
        pass

    @abstractmethod
    def update(self, data: bytes) -> None:
        pass

    @abstractmethod
    def digest(self) -> bytes:
        pass
