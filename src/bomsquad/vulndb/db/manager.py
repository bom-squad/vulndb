import logging
from contextlib import contextmanager
from textwrap import dedent
from typing import Generator
from typing import List

import psycopg2
from psycopg2.extensions import connection
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from psycopg2.sql import Identifier
from psycopg2.sql import Literal
from psycopg2.sql import SQL

from bomsquad.vulndb.config import instance as config

logger = logging.getLogger(__name__)


class DatabaseManager:
    @contextmanager
    def _db(self, database: str = "postgres") -> Generator[connection, None, None]:
        conn = psycopg2.connect(database=database)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        try:
            yield conn
        finally:
            conn.close()

    def _execute_or_show(
        self, conn: connection, commands: List[str], show_only: bool = True
    ) -> None:
        for command in commands:
            if show_only:
                print(f"{command};")
            else:
                cursor = conn.cursor()
                cursor.execute(command)

    def create(self, show_only: bool = False) -> None:
        with self._db() as conn:
            commands = [
                SQL("CREATE DATABASE {}").format(Identifier(config.database)).as_string(conn)
            ]
            self._execute_or_show(conn, commands, show_only)

    def drop(self, show_only: bool = False) -> None:
        with self._db() as conn:
            commands = [
                SQL("DROP DATABASE IF EXISTS {}")
                .format(Identifier(config.database))
                .as_string(conn),
                SQL("DROP OWNED BY {}").format(Identifier(config.username)),
                SQL("DROP USER IF EXISTS {}").format(Identifier(config.username)).as_string(conn),
            ]
            self._execute_or_show(conn, commands, show_only)

    def create_tables(self, show_only: bool = False) -> None:
        tables = [
            """
            CREATE TABLE cve(
                id serial NOT NULL PRIMARY KEY,
                data jsonb NOT NULL
            );
            """,
            """
            CREATE TABLE cpe(
                id serial NOT NULL PRIMARY KEY,
                data jsonb NOT NULL
            );
            """,
            """
            CREATE TABLE osv(
                id serial NOT NULL PRIMARY KEY,
                ecosystem VARCHAR(64) NOT NULL DEFAULT '',
                data jsonb NOT NULL
            );
            """,
        ]
        indices = [
            """
            CREATE INDEX cve_id ON cve USING gin ((data->'id'));
            """,
            """
            CREATE INDEX cpe_name_id ON cpe USING gin ((data->'cpeNameId'));
            """,
            """
            CREATE INDEX osv_id ON osv USING gin((data->'id'));
            """,
            """
            CREATE INDEX osv_alias_id ON osv USING gin((data->'aliases'));
            """,
        ]
        with self._db(config.database) as conn:
            commands = [*[dedent(t) for t in tables], *[dedent(i) for i in indices]]
            self._execute_or_show(conn, commands, show_only)

    def create_user(self, show_only: bool = False) -> None:
        with self._db(config.database) as conn:
            commands = [
                SQL("CREATE USER {} WITH ENCRYPTED PASSWORD {}")
                .format(Identifier(config.username), Literal(config.password))
                .as_string(conn),
                SQL("GRANT CONNECT ON DATABASE {} TO {}")
                .format(Identifier(config.database), Identifier(config.username))
                .as_string(conn),
                SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}")
                .format(Identifier(config.username))
                .as_string(conn),
                SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}")
                .format(Identifier(config.username))
                .as_string(conn),
            ]
            self._execute_or_show(conn, commands, show_only)


instance = DatabaseManager()
