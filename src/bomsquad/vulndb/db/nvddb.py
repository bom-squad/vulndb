import logging
from datetime import datetime
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import Optional
from uuid import UUID

from bomsquad.vulndb.db.connection import instance as factory
from bomsquad.vulndb.db.error import InvalidDataError
from bomsquad.vulndb.db.error import RecordNotFoundError
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE

logger = logging.getLogger(__name__)


class NVDDB:
    def _materialize_cve(self, data: Dict[str, Any]) -> CVE:
        from pydantic import ValidationError

        try:
            return CVE.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def upsert_cve(self, cve: CVE) -> None:
        with factory.get(True) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO cve(id, last_modified, data) values(?, ?, ?)
                    ON CONFLICT DO UPDATE set last_modified=?, data=? WHERE id=?
                """,
                [cve.id, cve.lastModified, cve.json(), cve.lastModified, cve.json(), cve.id],
            )
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register insertion")
            conn.commit()

    def delete_cve(self, cve: CVE) -> None:
        with factory.get(True) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cve WHERE id=?", [cve.id])
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register delete")
            conn.commit()

    def cve_last_modified(self) -> Optional[datetime]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT last_modified from cve ORDER BY last_modified DESC limit 1;
                """
            )
            for (last_modified,) in cursor.fetchall():
                return cast(datetime, last_modified)
            else:
                return None

    def cve_by_id(self, id: str) -> CVE:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM cve WHERE id=?", [id])
            for (data,) in cursor.fetchall():
                return self._materialize_cve(data)
            else:
                raise RecordNotFoundError(f"No such CVE for id {id}")

    def cve_count(self) -> int:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM cve")
            (count,) = cursor.fetchone()
            return int(count)

    def cve_all(self) -> Iterable[CVE]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM cve")
            while results := cursor.fetchmany(256):
                for row in results:
                    (data,) = row
                    yield self._materialize_cve(data)

    def _materialize_cpe(self, data: Dict[str, Any]) -> CPE:
        from pydantic import ValidationError

        try:
            return CPE.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def upsert_cpe(self, cpe: CPE) -> None:
        with factory.get(True) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO cpe(id, last_modified, data) values(?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET last_modified=?, data=? WHERE id=?
                """,
                [
                    str(cpe.cpeNameId),
                    cpe.lastModified,
                    cpe.json(),
                    cpe.lastModified,
                    cpe.json(),
                    str(cpe.cpeNameId),
                ],
            )
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register insertion")
            conn.commit()

    def delete_cpe(self, cpe: CPE) -> None:
        with factory.get(True) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cpe WHERE id=?", [str(cpe.cpeNameId)])
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register delete")
            conn.commit()

    def cpe_last_modified(self) -> Optional[datetime]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT last_modified from cpe ORDER BY last_modified DESC limit 1;
                """
            )
            for (last_modified,) in cursor.fetchall():
                return cast(datetime, last_modified)
            else:
                return None

    def cpe_by_name_id(self, id: UUID) -> CPE:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT data FROM cpe WHERE id=?
                """,
                [str(id)],
            )
            for (data,) in cursor.fetchall():
                return self._materialize_cpe(data)
            else:
                raise RecordNotFoundError(f"No such CPE for name id {str(id)}")

    def cpe_count(self) -> int:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM cpe")
            (count,) = cursor.fetchone()
            return int(count)

    def cpe_all(self) -> Iterable[CPE]:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM cpe")
            while results := cursor.fetchmany(256):
                for row in results:
                    (data,) = row
                    yield self._materialize_cpe(data)


instance = NVDDB()
