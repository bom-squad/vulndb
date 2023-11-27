import logging
import sqlite3
from contextlib import contextmanager
from sqlite3 import Connection
from textwrap import dedent
from typing import Generator
from typing import List

from bomsquad.vulndb.config import instance as config

logger = logging.getLogger(__name__)


class DatabaseManager:
    @contextmanager
    def connect_admin(self) -> Generator[Connection, None, None]:
        dbpath = config.db.path.expanduser()
        dbpath.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(dbpath)
        try:
            yield conn
        finally:
            conn.close()

    def _execute_or_show(
        self, conn: Connection, commands: List[str], show_only: bool = True
    ) -> None:
        for command in commands:
            if show_only:
                print(f"{command};")
            else:
                try:
                    cursor = conn.cursor()
                    cursor.execute(command)
                except Exception as e:
                    logger.error(f"{e} [{command}]")
                    raise

    def create(self, show_only: bool = False) -> None:
        with self.connect_admin():
            pass

    def drop(self, show_only: bool = False) -> None:
        if config.db.path.exists() and show_only is False:
            config.db.path.unlink()

    def create_tables(self, show_only: bool = False) -> None:
        tables = [
            """
            CREATE TABLE IF NOT EXISTS cve(
                id VARCHAR(64) PRIMARY KEY NOT NULL,
                last_modified DATETIME NOT NULL,
                data JSON NOT NULL
            );
            """,
            """
            CREATE TABLE cpe(
                id VARCHAR(64) PRIMARY KEY NOT NULL,
                last_modified DATETIME NOT NULL,
                data JSON NOT NULL
            );
            """,
            """
            CREATE TABLE osv(
                ecosystem VARCHAR(64) NOT NULL,
                id VARCHAR(64) NOT NULL,
                last_modified DATETIME NOT NULL,
                data JSON NOT NULL,
                UNIQUE(ecosystem, id)
            );
            """,
            """
            CREATE TABLE aliases(
                id VARCHAR(64) PRIMARY KEY NOT NULL,
                alias VARCHAR(64) NOT NULL,
                FOREIGN KEY(id) REFERENCES osv(id)
                UNIQUE(id, alias)
            )
            """,
            """
            CREATE TABLE purl_osv(
                purl VARCHAR(256) PRIMARY KEY NOT NULL,
                osv_id VARCHAR(64) NOT NULL,
                FOREIGN KEY(osv_id) REFERENCES osv(id)
            )
            """,
        ]
        indices = [
            """
            CREATE INDEX idx_id_alias ON aliases(id, alias);
            """,
            """
            CREATE INDEX idx_purl_osv_id ON purl_osv(purl, osv_id)
            """,
        ]
        with self.connect_admin() as conn:
            commands = [*[dedent(t) for t in tables], *[dedent(i) for i in indices]]
            self._execute_or_show(conn, commands, show_only)


instance = DatabaseManager()
