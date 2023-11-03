import logging
from typing import List

from bomsquad.vulndb.db.connection import pool
from bomsquad.vulndb.db.error import InvalidDataError
from bomsquad.vulndb.db.osvdb import OSVDB

logger = logging.getLogger(__name__)


class TestOSVModel:
    def test_all_osv_records_validate(self, osvdb: OSVDB) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()

            for ecosystem in osvdb.ecosystems():
                total_records = 0
                errors: List[InvalidDataError] = []
                cursor.execute("SELECT data FROM osv WHERE ecosystem = %s", [ecosystem])
                while results := cursor.fetchmany(256):
                    for row in results:
                        total_records += 1
                        (data,) = row
                        try:
                            osvdb._materialize_openssf(data)
                        except InvalidDataError as ide:
                            errors.append(ide)
                            logger.error(f"{ide.data['id']}: {ide}")
                assert (
                    len(errors) == 0
                ), f"osv/{ecosystem} has {len(errors)} / {total_records} errors"
                logger.info(f"No errors in {total_records} osv/{ecosystem} records")
