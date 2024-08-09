#!/usr/bin/python3

from collections.abc import Iterable
from enum import IntEnum
from typing import Self

class TagClass(IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT_SPECIFIC = 2
    PRIVATE = 3

class TagDefinition(IntEnum):
    NONE = 0
    EXPLICIT = 1
    IMPLICIT = 2
    AUTOMATIC = 3

class TaggingType(NamedTuple):
    definition: TagDefinition
    tagClass: TagClass
    typeId: int

class Object:
    _components: list[Self]
    _disabled: bool
    _tagging: TaggingType|None

    def __init__(self, *,
            disabled: bool = False,
            tagging: TaggingType|None = None) -> None:
        _components = []
        self._disabled = disabled
        self._tagging = tagging

    # Manage components
    def __getitem__(self, index: int):
        if isinstance(index, int):
            return self._components[index]
        return islice(self._components, index.start, index.stop, index.step)

    def __len__(self) -> int:
        return len(self._components)

    def __iter__(self) -> Iterable:
        return iter(self._components)

    # 
