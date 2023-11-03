import logging
from datetime import datetime
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import Optional
from uuid import UUID

from bomsquad.vulndb.db.connection import pool
from bomsquad.vulndb.db.error import InvalidDataError
from bomsquad.vulndb.db.error import RecordNotFoundError
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE

logger = logging.getLogger(__name__)


class NVDDB:
    def _materialize_cve(self, data: Dict[Any, Any]) -> CVE:
        from pydantic import ValidationError

        try:
            return CVE.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def upsert_cve(self, cve: CVE) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cve WHERE data->'id' ? %s", [cve.id])
            cursor.execute("INSERT INTO cve(data) values(%s)", [cve.json()])
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register insertion")
            conn.commit()

    def delete_cve(self, cve: CVE) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cve WHERE data->'id' ? %s", [cve.id])
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register delete")
            conn.commit()

    def cve_last_modified(self) -> Optional[datetime]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT (data->>'lastModified')::timestamp with time zone AS timestamp from cve ORDER BY timestamp DESC limit 1;
                """
            )
            if cursor.rowcount < 1:
                return None
            (timestamp,) = cursor.fetchone()
            return cast(datetime, timestamp)

    def cve_by_id(self, id: str) -> CVE:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT data FROM cve WHERE data->'id' ? %s
                """,
                [id],
            )
            if cursor.rowcount == 0:
                raise RecordNotFoundError(f"No such CVE for id {id}")

            (data,) = cursor.fetchone()
            return self._materialize_cve(data)

    def cve_count(self) -> int:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM cve")
            (count,) = cursor.fetchone()
            return int(count)

    def cve_all(self) -> Iterable[CVE]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM cve")
            while results := cursor.fetchmany(256):
                for row in results:
                    (data,) = row
                    yield self._materialize_cve(data)

    def _materialize_cpe(self, data: Dict[Any, Any]) -> CPE:
        from pydantic import ValidationError

        try:
            return CPE.model_validate(data)
        except ValidationError as ve:
            raise InvalidDataError(ve, data)

    def upsert_cpe(self, cpe: CPE) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cpe WHERE data->'cpeNameId' ? %s", [str(cpe.cpeNameId)])
            cursor.execute("INSERT INTO cpe(data) values(%s)", [cpe.json()])
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register insertion")
            conn.commit()

    def delete_cpe(self, cpe: CPE) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cpe WHERE data->'cpeNameId' ? %s", [str(cpe.cpeNameId)])
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register delete")
            conn.commit()

    def cpe_last_modified(self) -> Optional[datetime]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT (data->>'lastModified')::timestamp with time zone AS timestamp from cpe ORDER BY timestamp DESC limit 1;
                """
            )
            if cursor.rowcount < 1:
                return None
            (timestamp,) = cursor.fetchone()
            return cast(datetime, timestamp)

    def cpe_by_name_id(self, id: UUID) -> CPE:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT data FROM cpe WHERE data->'cpeNameId' ? %s
                """,
                [str(id)],
            )
            if cursor.rowcount == 0:
                raise RecordNotFoundError(f"No such CPE for name id {str(id)}")

            (data,) = cursor.fetchone()
            return self._materialize_cpe(data)

    def cpe_count(self) -> int:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM cpe")
            (count,) = cursor.fetchone()
            return int(count)

    def cpe_all(self) -> Iterable[CPE]:
        with pool.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM cpe")
            while results := cursor.fetchmany(256):
                for row in results:
                    (data,) = row
                    yield self._materialize_cpe(data)


instance = NVDDB()
