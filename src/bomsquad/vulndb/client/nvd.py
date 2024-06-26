import json
import logging
import time
from abc import abstractmethod
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Generator
from typing import Generic
from typing import Iterator
from typing import Optional
from typing import TypeVar
from urllib.parse import quote as urlquote

import requests
from retry import retry

from bomsquad.vulndb.config import instance as config
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE

logger = logging.getLogger(__name__)


T = TypeVar("T", CVE, CPE)


class NVDResultSet(Generic[T]):
    results_per_page: int
    start_index: int
    total_results: int
    version: str
    timestamp: datetime

    _results: dict[str, Any]
    _result_key: str
    _limit: int | None

    _result_iterator: Iterator[dict[str, Any]]
    _result_count: int

    def __init__(self, result_key: str, results: dict[str, Any], limit: int | None = None) -> None:
        self.results_per_page = results["resultsPerPage"]
        self.start_index = results["startIndex"]
        self.total_results = results["totalResults"]
        self.version = results["version"]
        self.timestamp = datetime.fromisoformat(results["timestamp"])

        self._results = results
        self._result_key = result_key
        self._limit = limit

        self._result_iterator = iter(self._results[self._result_key])
        self._result_count = 0

    def __iter__(self) -> Iterator[T]:
        return self

    def __next__(self) -> T:
        if self._limit and self._result_count > self._limit:
            raise StopIteration()
        self._result_count += 1

        return self._to_record(next(self._result_iterator))

    # Since TypeVars do not permit invocation of static methods, we will solve
    # this part rather stupidly with inheritance.
    @abstractmethod
    def _to_record(self, result: dict[str, Any]) -> T:
        pass


class CPEResultSet(NVDResultSet[CPE]):
    def _to_record(self, result: dict[str, Any]) -> CPE:
        return CPE.model_validate(result["cpe"])


class CVEResultSet(NVDResultSet[CVE]):
    def _to_record(self, result: dict[str, Any]) -> CVE:
        return CVE.model_validate(result["cve"])


class NVD:
    CVE_STEM = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CPE_STEM = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

    @retry(Exception, backoff=1, tries=10, max_delay=5, logger=logger)
    def vulnerabilities(
        self,
        offset: int = 0,
        limit: Optional[int] = None,
        last_mod_start_date: Optional[datetime] = None,
        **kwargs: str,
    ) -> Generator[NVDResultSet[CVE], None, None]:
        while True:
            url = f"{self.CVE_STEM}?startIndex={offset}"
            if last_mod_start_date:
                dtstart = last_mod_start_date.isoformat()
                dtend = datetime.now(timezone.utc).isoformat()
                url += f"&lastModStartDate={urlquote(dtstart)}&lastModEndDate={urlquote(dtend)}"
                logger.info(f"Querying from {offset} - {limit} and {dtstart} - {dtend}")
            headers = {"Accept": "application/json"}
            if config.nvd_api_key:
                headers["apiKey"] = config.nvd_api_key

            r = requests.get(url, headers=headers)
            if r.status_code != 200:
                r.raise_for_status()

            results = CVEResultSet("vulnerabilities", json.loads(r.text), limit)
            if results.total_results > 0 and results.results_per_page > 0:
                yield results
            else:
                break

            time.sleep(config.request_delay)

    @retry(Exception, backoff=1, tries=10, max_delay=5, logger=logger)
    def products(
        self,
        offset: int = 0,
        limit: Optional[int] = None,
        last_mod_start_date: Optional[datetime] = None,
    ) -> Generator[datetime | CPE, None, None]:
        total_results = 0
        first_ts = None
        while True:
            url = f"{self.CPE_STEM}?startIndex={offset}"
            if last_mod_start_date:
                dtstart = last_mod_start_date.isoformat()
                dtend = datetime.now(timezone.utc).isoformat()
                url += f"&lastModStartDate={urlquote(dtstart)}&lastModEndDate={urlquote(dtend)}"
                logger.info(f"Querying from {offset} - {limit} and {dtstart} - {dtend}")
            headers = {"Accept": "application/json"}
            if config.nvd_api_key:
                headers["apiKey"] = config.nvd_api_key

            r = requests.get(url, headers=headers)
            if r.status_code != 200:
                r.raise_for_status()

            jres = json.loads(r.text)
            if first_ts is None:
                first_ts = datetime.fromisoformat(jres["timestamp"])
                yield first_ts
            if jres["totalResults"] > 0:
                logger.info(
                    f"Materializing CPE {offset}-{offset + jres['resultsPerPage']} / {jres['totalResults']}"
                )
            for jso in jres["products"]:
                yield CPE.parse_obj(jso["cpe"])
                total_results += 1
                offset += 1
                if limit and total_results >= limit:
                    return

            if jres["resultsPerPage"] <= 0:
                return

            time.sleep(config.request_delay)
