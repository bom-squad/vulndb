import logging
from datetime import datetime
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import Optional

from packageurl import PackageURL

from bomsquad.vulndb.db.connection import instance as factory
from bomsquad.vulndb.db.error import InvalidDataError
from bomsquad.vulndb.db.error import RecordNotFoundError
from bomsquad.vulndb.model.openssf import OpenSSF

logger = logging.getLogger(__name__)


class OSVDB:
    def upsert(self, ecosystem: str, openssf: OpenSSF) -> None:
        with factory.get(True) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO osv(ecosystem, id, last_modified, data) values(?, ?, ?, ?)
                    ON CONFLICT(ecosystem, id) DO UPDATE SET data=?
                """,
                [ecosystem, openssf.id, openssf.modified, openssf.json(), openssf.json()],
            )
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register insertion")
            for alias in openssf.aliases:
                cursor.execute(
                    "INSERT INTO aliases(id, alias) VALUES(?, ?) ON CONFLICT DO NOTHING",
                    [openssf.id, alias],
                )
            for affected in openssf.affected:
                if affected.package and affected.package.purl:
                    cursor.execute(
                        "INSERT INTO purl_osv(purl, osv_id) VALUES(?, ?) ON CONFLICT DO NOTHING",
                        [affected.package.purl, openssf.id],
                    )
            conn.commit()

    def delete(self, ecosystem: str, openssf: OpenSSF) -> None:
        with factory.get(True) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM osv WHERE ecosystem = ? AND id == ?",
                [ecosystem, str(openssf.id)],
            )
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register delete")
            conn.commit()

    def last_modified(self) -> Optional[datetime]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT last_modified FROM osv ORDER BY last_modified DESC limit 1;
                """
            )
            for (last_modified,) in cursor.fetchall():
                return cast(datetime, last_modified)
            else:
                return None

    def last_modified_in_ecosystem(self, ecosystem: str) -> Optional[datetime]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT last_modified FROM osv WHERE ecosystem = ? ORDER BY last_modified DESC limit 1;
                """,
                [ecosystem],
            )
            for (last_modified,) in cursor.fetchall():
                return cast(datetime, last_modified)
            else:
                return None

    def _materialize_openssf(self, data: Dict[Any, Any]) -> OpenSSF:
        from pydantic import ValidationError

        try:
            return OpenSSF.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def find_by_purl(self, purl: PackageURL) -> Iterable[OpenSSF]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT DISTINCT osv.id, osv.data
                    FROM purl_osv pv LEFT JOIN osv ON osv.id=pv.osv_id
                    WHERE pv.purl=?
                """,
                [purl.to_string()],
            )
            while results := cursor.fetchmany(64):
                for row in results:
                    _, data = row

                    yield self._materialize_openssf(data)

    def ecosystems(self) -> Iterable[str]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT distinct ecosystem FROM osv")
            for row in cursor.fetchall():
                (ecosystem,) = row
                yield ecosystem

    def count_all(self) -> int:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM osv")
            (count,) = cursor.fetchone()
            return int(count)

    def count(self, ecosystem: str) -> int:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM osv WHERE ecosystem = ?", [ecosystem])
            (count,) = cursor.fetchone()
            return int(count)

    def all(self) -> Iterable[OpenSSF]:
        for ecosystem in self.ecosystems():
            yield from self.all_from_ecosystem(ecosystem)

    def all_from_ecosystem(self, ecosystem: str) -> Iterable[OpenSSF]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM osv WHERE ecosystem = ?", [ecosystem])
            while results := cursor.fetchmany(256):
                for row in results:
                    (data,) = row
                    yield self._materialize_openssf(data)

    def find_by_id_or_alias(self, id: str) -> Iterable[OpenSSF]:
        with factory.get() as conn:
            cursor = conn.cursor()
            found_one = False
            cursor.execute(
                """
                SELECT DISTINCT osv.id, osv.data
                    FROM osv LEFT JOIN aliases a ON osv.id=a.id WHERE osv.id=? OR a.alias=?
                """,
                [id, id],
            )
            for id, data in cursor.fetchall():
                found_one = True
                yield self._materialize_openssf(data)
            else:
                if not found_one:
                    raise RecordNotFoundError(f"No records found for id/alias {id}")


instance = OSVDB()
