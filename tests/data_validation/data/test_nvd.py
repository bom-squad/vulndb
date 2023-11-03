import logging
from typing import List

from bomsquad.vulndb.db.connection import pool
from bomsquad.vulndb.db.error import InvalidDataError
from bomsquad.vulndb.db.nvddb import NVDDB

logger = logging.getLogger(__name__)


class TestNVDModel:
    def test_all_cve_records_validate(self, nvddb: NVDDB) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()

            total_records = 0
            errors: List[InvalidDataError] = []
            cursor.execute("SELECT data FROM cve")
            while results := cursor.fetchmany(256):
                for row in results:
                    total_records += 1
                    (data,) = row
                    try:
                        nvddb._materialize_cve(data)
                    except InvalidDataError as ide:
                        errors.append(ide)
                        logger.error(f"{ide.data['id']}: {ide}")
            assert len(errors) == 0, f"cve has {len(errors)} / {total_records} errors"
            logger.info(f"No errors in {total_records} cve records")

    def test_all_cpe_records_validate(self, nvddb: NVDDB) -> None:
        with pool.get() as conn:
            cursor = conn.cursor()

            total_records = 0
            errors: List[InvalidDataError] = []
            cursor.execute("SELECT data FROM cpe")
            while results := cursor.fetchmany(256):
                for row in results:
                    total_records += 1
                    (data,) = row
                    try:
                        nvddb._materialize_cpe(data)
                    except InvalidDataError as ide:
                        errors.append(ide)
                        logger.error(f"{ide.data['id']}: {ide}")
            assert len(errors) == 0, f"cpe has {len(errors)} / {total_records} errors"
            logger.info(f"No errors in {total_records} cpe records")
