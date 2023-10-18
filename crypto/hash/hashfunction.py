#!/usr/bin/python3

from abc import ABC, ABCMeta, abstractmethod

class MetaHashFunction(ABCMeta):
    def __new__(metacls, cls, bases, classdict, **kwargs):
        try:
            block_size = classdict['block_size']
            digest_size = classdict['digest_size']
        except:
            raise KeyError('properties block_size and digest_size must be presented')
        classdict['name'] = property(lambda _: cls)
        classdict['block_size'] = property(lambda _: block_size)
        classdict['digest_size'] = property(lambda _: digest_size)

        try:
            init = classdict['init']
            update = classdict['update']
            final = classdict['final']
        except:
            raise KeyError('methods init, update, final must be presented')
        del classdict['init'], classdict['final']
        classdict['_init'] = init
        classdict['digest'] = final
        classdict['hexdigest'] = lambda self: self.digest().hex()
        classdict['__init__'] = metacls.func_init

        exc = None
        try:
            hash_func = super().__new__(metacls, cls, bases, classdict, **kwargs)
        except RuntimeError as e:
            exc = e.__cause__ or e
        if exc is not None:
            raise exc
        return hash_func

    def func_init(self, data: bytes|None = None):
        self._init()
        if data is not None:
            self.update(data)

class HashFunction(ABC, metaclass = MetaHashFunction):
    block_size: int = 0
    digest_size: int = 0

    @abstractmethod
    def init(self) -> None:
        pass

    @abstractmethod
    def update(self, data: bytes) -> None:
        pass

    @abstractmethod
    def final(self) -> bytes:
        pass
