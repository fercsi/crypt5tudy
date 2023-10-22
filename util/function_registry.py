#!/usr/bin/python3

from typing import Callable

class FunctionRegistry:
    _registered: dict[str, Callable] = {}

    @classmethod
    def add(cls, function: Callable, name: str|None = None) -> None:
        if name is None:
            name = function().name
        cls._registered[name.lower()] = function

    @classmethod
    def remove(cls, name: str) -> Callable:
        name = name.lower()
        if name in cls._registered:
            del cls._registered[name]

    @classmethod
    def get(cls, name: str) -> Callable|None:
        return cls._registered.get(name.lower(), None)
