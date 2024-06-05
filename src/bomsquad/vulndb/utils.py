from typing import Any
from typing import Generator


class GenWrap:
    def __init__(self, gen: Generator[Any, Any, Any]) -> None:
        self.gen = gen

    def __iter__(self) -> Any:
        self.value = yield from self.gen
        return self.value
