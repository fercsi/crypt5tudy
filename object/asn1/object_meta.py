#!/usr/bin/python3

from abc import ABC, ABCMeta, abstractmethod

class ObjectMeta(ABCMeta):
    def __new__(metacls, cls, bases, classdict, **kwargs):
        classdict['__name'] = property(lambda _: cls)
        components = None
        if 'components' in classdict:
            components = classdict['components']
            del classdict['components']
        # encapsulated etc.

        if components:
            for i, (name, _, _) in enumerate(components):
                classdict[name] = metacls._create_property(i)

            classdict['__init__'] = metacls.create_init(components)

        # create class
        exc = None
        try:
            ext_class = super().__new__(metacls, cls, bases, classdict, **kwargs)
        except RuntimeError as e:
            exc = e.__cause__ or e
        if exc is not None:
            raise exc
        return ext_class

    @classmethod
    def _create_init(cls, components):
        def _init(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            for _, ctype, init_args in components:
                component = ctype(**init_args)
                self._components.append(component)
        return _init

    @classmethod
    def _create_property(metacls, idx):
        def _prop(self):
            self._component[idx]
        return property(_prop)
