import logging
from datetime import datetime
from typing import Any
from typing import Generator
from typing import Iterator
from typing import Optional

from bomsquad.vulndb.client.nvd import NVD
from bomsquad.vulndb.client.nvd import NVDResultSet
from bomsquad.vulndb.client.osv import OSV
from bomsquad.vulndb.db.checkpoints import Checkpoints
from bomsquad.vulndb.db.nvddb import instance as nvddb
from bomsquad.vulndb.db.osvdb import instance as osvdb

logger = logging.getLogger(__name__)


class _NVDResultGen:
    result_sets: Generator[NVDResultSet[Any], None, None]
    current: NVDResultSet[Any]
    first_ts: datetime

    def __init__(self, result_sets: Generator[NVDResultSet[Any], None, None]) -> None:
        self.result_sets = result_sets
        self.current = next(self.result_sets)
        self.first_ts = self.current.timestamp

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        try:
            return next(self.current)
        except StopIteration:
            self.current = next(self.result_sets)
            return next(self)


class Ingest:
    @classmethod
    def cve(
        cls,
        update: bool = False,
    ) -> None:
        api = NVD()
        cp = Checkpoints()
        gen = _NVDResultGen(
            api.vulnerabilities(
                offset=0, last_mod_start_date=cp.last_updated("cve") if update else None
            )
        )

        for cve in gen:
            nvddb.upsert_cve(cve)
        cp.upsert("cve", gen.first_ts)

    @classmethod
    def cpe(
        cls,
        update: bool = False,
    ) -> None:
        api = NVD()
        cp = Checkpoints()
        gen = _NVDResultGen(
            api.products(offset=0, last_mod_start_date=cp.last_updated("cpe") if update else None)
        )

        for cpe in gen:
            nvddb.upsert_cpe(cpe)
        cp.upsert("cpe", gen.first_ts)

    @classmethod
    def all_osv(cls) -> None:
        for ecosystem in OSV.ECOSYSTEMS:
            logger.info(f"Ingesting {ecosystem}")
            cls.osv(ecosystem)
            logger.info(f"{ecosystem} complete")

    @classmethod
    def osv(cls, ecosystem: str, offset: int = 0, limit: Optional[int] = None) -> None:
        api = OSV()
        for openssf in api.all(ecosystem):
            osvdb.upsert(ecosystem, openssf)
