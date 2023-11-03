import logging
from typing import Optional

import tomli
from pydantic import BaseModel

from bomsquad.vulndb.config_resolver import ConfigResolver

logger = logging.getLogger(__name__)


class Config(BaseModel):
    min_conn: int = 1
    max_conn: int = 10
    database: str
    username: str
    password: str
    nvd_api_key: Optional[str] = None
    request_delay: int

    @classmethod
    def load(cls) -> "Config":
        with ConfigResolver.resolve_config().open("rb") as fh:
            obj = tomli.load(fh)["vulndb"]
            config = Config.parse_obj(obj)
            return config


instance = Config.load()
