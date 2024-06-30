from __future__ import annotations

from enum import Enum


class NVDEnum(str, Enum):
    @classmethod
    def _missing_(cls, value: object) -> NVDEnum | None:
        assert type(value) is str
        converted = value.replace(" ", "_").upper()
        if converted in cls.__members__.keys():
            return cls(converted)
        return None
