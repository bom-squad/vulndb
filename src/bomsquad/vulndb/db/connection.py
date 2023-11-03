import logging
from contextlib import contextmanager
from typing import Generator
from typing import Optional

from psycopg2.extensions import connection
from psycopg2.pool import ThreadedConnectionPool

from bomsquad.vulndb.config import instance as config

logger = logging.getLogger(__name__)


class ConnectionPool:
    _active_pool: Optional[ThreadedConnectionPool] = None

    @property
    def _pool(self) -> ThreadedConnectionPool:
        if self._active_pool is None:
            logger.debug("Starting connection pool ...")
            self._active_pool = ThreadedConnectionPool(
                config.min_conn,
                config.max_conn,
                user=config.username,
                password=config.password,
                database=config.database,
            )
        return self._active_pool

    @contextmanager
    def get(self) -> Generator[connection, None, None]:
        conn = self._pool.getconn()
        try:
            yield conn
        finally:
            self._pool.putconn(conn)

    def is_open(self) -> bool:
        return self._active_pool is not None

    def close(self) -> None:
        logger.debug("Closing down connection pool")
        try:
            if self._active_pool:
                self._active_pool.closeall()
        finally:
            self._active_pool = None


pool = ConnectionPool()
