#!/usr/bin/python3

from typing import Callable

class Registry:
    _registered_hash_functions: dict[str, Callable] = {}

    @classmethod
    def add(cls, function: Callable, name: str|None = None) -> None:
        if name is None:
            name = function().name
        cls._registered_hash_functions[name.lower()] = function

    @classmethod
    def remove(cls, name: str) -> Callable:
        name = name.lower()
        if name in cls._registered_hash_functions:
            del cls._registered_hash_functions[name]

    @classmethod
    def get(cls, name: str) -> Callable|None:
        return cls._registered_hash_functions.get(name.lower(), None)
