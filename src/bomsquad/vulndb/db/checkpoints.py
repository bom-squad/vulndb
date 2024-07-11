import logging
from datetime import datetime
from typing import cast

from bomsquad.vulndb.db.connection import instance as factory

logger = logging.getLogger(__name__)


class Checkpoints:
    def upsert(self, source: str, last_updated: datetime) -> None:
        with factory.get(True) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO checkpoints(source, last_updated) values(?, ?)
                    ON CONFLICT DO UPDATE set last_updated=? WHERE source=?
                """,
                [source, last_updated, last_updated, source],
            )
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register insertion")
            conn.commit()

    def delete(self, source: str) -> None:
        with factory.get(True) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM checkpoints WHERE source=?", [source])
            if cursor.rowcount < 1:
                raise RuntimeError("Database did not register delete")
            conn.commit()

    def last_updated(self, source: str) -> datetime | None:
        with factory.get() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT last_updated from checkpoints where source=?", [source])
            for (last_updated,) in cursor.fetchall():
                return cast(datetime, last_updated)
            else:
                return None
