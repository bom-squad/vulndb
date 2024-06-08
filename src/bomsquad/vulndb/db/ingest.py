import logging
from datetime import datetime
from typing import Any
from typing import cast
from typing import Generator
from typing import Optional

from bomsquad.vulndb.client.nvd import NVD
from bomsquad.vulndb.client.osv import OSV
from bomsquad.vulndb.db.checkpoints import Checkpoints
from bomsquad.vulndb.db.nvddb import instance as nvddb
from bomsquad.vulndb.db.osvdb import instance as osvdb

logger = logging.getLogger(__name__)


class GenWrap:
    def __init__(self, gen: Generator[Any, Any, Any]) -> None:
        self.gen = gen

    def __iter__(self) -> Any:
        self.value = yield from self.gen
        return self.value


class Ingest:
    @classmethod
    def cve(
        cls,
        update: bool = False,
    ) -> None:
        api = NVD()
        cp = Checkpoints()
        gen = GenWrap(
            api.vulnerabilities(
                offset=0, last_mod_start_date=cp.last_updated("cve") if update else None
            )
        )
        for cve in gen:
            nvddb.upsert_cve(cve)
        first_ts = cast(datetime, gen.value)
        if first_ts:
            cp.upsert("cve", first_ts)

    @classmethod
    def cpe(
        cls,
        update: bool = False,
    ) -> None:
        api = NVD()
        cp = Checkpoints()
        gen = GenWrap(
            api.products(offset=0, last_mod_start_date=cp.last_updated("cpe") if update else None)
        )
        for cpe in gen:
            nvddb.upsert_cpe(cpe)
        first_ts = cast(datetime, gen.value)
        if first_ts:
            cp.upsert("cpe", first_ts)

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
