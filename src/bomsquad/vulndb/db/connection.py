import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from datetime import timezone
from threading import local
from typing import Any
from typing import cast
from typing import Dict
from typing import Generator

from bomsquad.vulndb.config import instance as config

logger = logging.getLogger(__name__)


class ConnectionFactory:
    _conn: Any = None
    _writable: Any = None

    @classmethod
    def _adapt_timestamp(cls, value: datetime) -> float:
        dt = value

        if value.tzinfo is None:
            dt = value.replace(tzinfo=timezone.utc)

        return dt.timestamp()

    @classmethod
    def _convert_timestamp(cls, value: bytes) -> datetime:
        return datetime.fromtimestamp(float(value), timezone.utc)

    @classmethod
    def _adapt_json_data(cls, value: Dict[str, Any]) -> str:
        return json.dumps(value)

    @classmethod
    def _convert_json_data(cls, value: bytes) -> Dict[str, Any]:
        return cast(Dict[str, Any], json.loads(value))

    @contextmanager
    def get(self, writer: bool = False) -> Generator[sqlite3.Connection, None, None]:
        if self._conn and writer and self._writable.v is False:
            self.close()
        if not self._conn:
            self._conn = local()
            self._conn.v = self._connect(writer)
            self._writable = local()
            self._writable.v = writer

        yield cast(sqlite3.Connection, self._conn.v)

    def _connect(self, writer: bool = False) -> sqlite3.Connection:
        sqlite3.register_adapter(datetime, self._adapt_timestamp)
        sqlite3.register_converter("datetime", self._convert_timestamp)
        sqlite3.register_adapter(dict, self._adapt_json_data)
        sqlite3.register_converter("json", self._convert_json_data)
        uri = f"file:{config.db.path.expanduser()}{'?mode=ro' if writer is False else ''}"

        return sqlite3.connect(uri, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

    def is_open(self) -> bool:
        return self._conn is not None

    def close(self) -> None:
        if self._conn:
            conn = cast(sqlite3.Connection, self._conn.v)
            conn.close()
            self._conn = None
            self._writable = None


instance = ConnectionFactory()
