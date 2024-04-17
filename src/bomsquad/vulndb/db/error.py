from typing import Any
from typing import Dict

from pydantic import ValidationError


class InvalidConfigurationError(Exception):
    pass


class RecordNotFoundError(Exception):
    pass


class InvalidDataError(Exception):
    def __init__(self, error: ValidationError, data: Dict[Any, Any]) -> None:
        super().__init__(str(error))
        self.data = data
