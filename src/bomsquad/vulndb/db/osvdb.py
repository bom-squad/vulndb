import logging
from datetime import datetime
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import Optional

from packageurl import PackageURL

from bomsquad.vulndb.db.connection import pool
from bomsquad.vulndb.db.error import InvalidDataError
from bomsquad.vulndb.db.error import RecordNotFoundError
from bomsquad.vulndb.model.openssf import OpenSSF

logger = logging.getLogger(__name__)


class OSVDB:
    def upsert(self, ecosystem: str, openssf: OpenSSF) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM osv WHERE ecosystem = %s AND data->'id' ? %s",
                [ecosystem, str(openssf.id)],
            )
            cursor.execute(
                "INSERT INTO osv(ecosystem, data) values(%s, %s)", [ecosystem, openssf.json()]
            )
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register insertion")
            conn.commit()

    def delete(self, ecosystem: str, openssf: OpenSSF) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM osv WHERE ecosystem = %s AND data->'id' ? %s",
                [ecosystem, str(openssf.id)],
            )
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register delete")
            conn.commit()

    def last_modified(self) -> Optional[datetime]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT (data->>'modified')::timestamp with time zone AS timestamp
                    FROM osv ORDER BY timestamp DESC limit 1;
                """
            )
            if cursor.rowcount < 1:
                return None
            (timestamp,) = cursor.fetchone()
            return cast(datetime, timestamp)

    def last_modified_in_ecosystem(self, ecosystem: str) -> Optional[datetime]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT (data->>'modified')::timestamp with time zone AS timestamp
                    FROM osv WHERE ecosystem = %s ORDER BY timestamp DESC limit 1;
                """,
                [ecosystem],
            )
            if cursor.rowcount < 1:
                return None
            (timestamp,) = cursor.fetchone()
            return cast(datetime, timestamp)

    def _materialize_openssf(self, data: Dict[Any, Any]) -> OpenSSF:
        from pydantic import ValidationError

        try:
            return OpenSSF.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def find_by_purl(self, purl: PackageURL) -> Iterable[OpenSSF]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    DISTINCT data->'id' AS id, data
                FROM osv,jsonb_array_elements(data->'affected') AS affected
                WHERE data @@ %s;
                """,
                [f'$.affected[*].package.purl == "{purl.to_string()}"'],
            )
            while results := cursor.fetchmany(64):
                for row in results:
                    _, data = row

                    yield self._materialize_openssf(data)

    def ecosystems(self) -> Iterable[str]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT distinct ecosystem FROM osv")
            for row in cursor.fetchall():
                (ecosystem,) = row
                yield ecosystem

    def count_all(self) -> int:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM osv")
            (count,) = cursor.fetchone()
            return int(count)

    def count(self, ecosystem: str) -> int:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM osv WHERE ecosystem = %s", [ecosystem])
            (count,) = cursor.fetchone()
            return int(count)

    def all(self) -> Iterable[OpenSSF]:
        for ecosystem in self.ecosystems():
            yield from self.all_from_ecosystem(ecosystem)

    def all_from_ecosystem(self, ecosystem: str) -> Iterable[OpenSSF]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM osv WHERE ecosystem = %s", [ecosystem])
            while results := cursor.fetchmany(256):
                for row in results:
                    (data,) = row
                    yield self._materialize_openssf(data)

    def find_by_id_or_alias(self, id: str) -> Iterable[OpenSSF]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    DISTINCT data->'id', data
                FROM osv, jsonb_array_elements(data->'aliases') AS alias
                WHERE data->'id' ? %s OR alias ? %s
                """,
                [id, id],
            )
            if cursor.rowcount <= 0:
                raise RecordNotFoundError(f"No records found for id/alias {id}")
            for row in cursor.fetchall():
                _, data = row
                yield self._materialize_openssf(data)


instance = OSVDB()
