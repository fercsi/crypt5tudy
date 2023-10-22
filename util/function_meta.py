#!/usr/bin/python3

import copy
from abc import ABC, ABCMeta, abstractmethod

class FunctionMeta(ABCMeta):
    def __new__(metacls, cls, bases, classdict, **kwargs):
        classdict['name'] = property(lambda _: cls)

        classdict['_function_creator'] = metacls.__name__

        exc = None
        try:
            function = super().__new__(metacls, cls, bases, classdict, **kwargs)
        except RuntimeError as e:
            exc = e.__cause__ or e
        if exc is not None:
            raise exc
        return function

    @classmethod
    def _create_property(metacls, cls, bases, classdict, field):
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
                if getattr(base, '_function_creator', '') == metacls.__name__:
                    return
                if hasattr(base, field):
                    return
        raise KeyError(field + ' is missing')
