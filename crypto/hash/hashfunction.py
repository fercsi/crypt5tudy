#!/usr/bin/python3

import copy
from abc import ABC, abstractmethod
from util.function_meta import FunctionMeta

class HashFunctionMeta(FunctionMeta):
    def __new__(metacls, cls, bases, classdict, **kwargs):
        metacls._create_property(cls, bases, classdict, 'digest_size')
        metacls._create_property(cls, bases, classdict, 'block_size')

        classdict['hexdigest'] = lambda self: self.digest().hex()
        classdict['copy'] = lambda self: copy.deepcopy(self)
        classdict['__init__'] = metacls.func_init

        return super().__new__(metacls, cls, bases, classdict, **kwargs)

    def func_init(self, data: bytes|None = None, **kwargs):
        self.init(**kwargs)
        if data is not None:
            self.update(data)


class HashFunction(ABC, metaclass = HashFunctionMeta):
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
