#!/usr/bin/python3

import copy
from abc import ABC, ABCMeta, abstractmethod

class MetaHashFunction(ABCMeta):
    def __new__(metacls, cls, bases, classdict, **kwargs):
        classdict['name'] = property(lambda _: cls)

        metacls._create_property(cls, bases, classdict, 'digest_size')
        metacls._create_property(cls, bases, classdict, 'block_size')

        classdict['hexdigest'] = lambda self: self.digest().hex()
        classdict['copy'] = lambda self: copy.deepcopy(self)
        classdict['__init__'] = metacls.func_init
        classdict['_is_hash_function'] = True

        exc = None
        try:
            hash_func = super().__new__(metacls, cls, bases, classdict, **kwargs)
        except RuntimeError as e:
            exc = e.__cause__ or e
        if exc is not None:
            raise exc
        return hash_func

    def func_init(self, data: bytes|None = None, **kwargs):
        self.init(**kwargs)
        if data is not None:
            self.update(data)

    @classmethod
    def _create_property(_, cls, bases, classdict, field):
        if field in classdict:
            value = classdict[field]
            if value is None:
                value_field = '_' + field
                classdict[value_field] = None
                classdict[field] = property(lambda self: getattr(self, value_field))
            else:
                classdict[field] = property(lambda _: value)
            return
        for chain in bases:
            for base in chain.__mro__:
                if getattr(base, '_is_hash_function', False):
                    return
                if hasattr(base, field):
                    return
        raise KeyError(field + ' is missing')

class HashFunction(ABC, metaclass = MetaHashFunction):
    digest_size: int = 1
    block_size: int = 1

    @abstractmethod
    def init(self) -> None:
        pass

    @abstractmethod
    def update(self, data: bytes) -> None:
        pass

    @abstractmethod
    def digest(self) -> bytes:
        pass
