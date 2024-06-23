import json
import logging
import re
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs
from urllib.parse import urlparse

import responses
from requests.models import PreparedRequest

from bomsquad.vulndb.client.nvd import NVD
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE

logger = logging.getLogger(__name__)


class TestVulnerabilities:
    cve_examples = Path(__file__).parent / "examples/nvd/cve/"
    timestamps: list[datetime] = []

    def response_cb(self, req: PreparedRequest) -> tuple[int, dict[str, str], str]:
        status = 200
        headers: dict[str, str] = {}
        pageLimit = 1000
        urlquery = parse_qs(urlparse(req.path_url).query)
        startIndex = int(urlquery["startIndex"][-1])
        resultsPerPage = (
            int(urlquery["resultsPerPage"][-1]) if "resultsPerPage" in urlquery else None
        )
        lastModStartDate = None
        lastModEndDate = None
        if "lastModStartDate" in urlquery:
            lastModStartDate = datetime.fromisoformat(urlquery["lastModStartDate"][-1])
            if lastModStartDate.tzinfo is None:
                lastModStartDate = lastModStartDate.replace(tzinfo=timezone.utc)
        if "lastModEndDate" in urlquery:
            lastModEndDate = datetime.fromisoformat(urlquery["lastModEndDate"][-1])
            if lastModEndDate.tzinfo is None:
                lastModEndDate = lastModEndDate.replace(tzinfo=timezone.utc)
        if resultsPerPage and pageLimit > resultsPerPage:
            pageLimit = resultsPerPage

        utcnow = datetime.utcnow()
        self.timestamps.append(utcnow)

        resp = {
            "startIndex": startIndex,
            "timestamp": utcnow.isoformat(),
        }

        vulns = []
        vulns_len = 0
        totalResults = 0
        if lastModStartDate and lastModEndDate:
            # Filter based on lastModified
            for cve in self.cve_examples.iterdir():
                cve_json = json.loads(cve.read_text())
                lastmod = cve_json["lastModified"]
                dt = lastmod.replace(tzinfo=timezone.utc)
                if dt >= lastModStartDate and dt < lastModEndDate:
                    if totalResults >= startIndex and vulns_len < pageLimit:
                        vulns.append(cve_json)
                        vulns_len += 1
                    totalResults += 1
        else:
            for cve in self.cve_examples.iterdir():
                if totalResults >= startIndex and vulns_len < pageLimit:
                    cve_json = json.loads(cve.read_text())
                    vulns.append(cve_json)
                    vulns_len += 1
                totalResults += 1

        assert vulns_len == len(vulns)

        resp["totalResults"] = totalResults
        resp["vulnerabilities"] = vulns
        resp["resultsPerPage"] = vulns_len
        return (status, headers, json.dumps(resp))

    @responses.activate
    def test_ingest(self) -> None:
        responses.add_callback(responses.GET, re.compile(".*"), callback=self.response_cb)
        self.timestamps = []
        nvd = NVD()
        gen = nvd.vulnerabilities(offset=0, limit=None, last_mod_start_date=None)
        dt = cast(datetime, next(gen))
        assert dt == self.timestamps[0]

        for cve_file in self.cve_examples.iterdir():
            cve = next(gen)
            cve_json = json.loads(cve_file.read_text())
            assert cve == CVE.model_validate(cve_json["cve"])


class TestProducts:
    cpe_examples = Path(__file__).parent / "examples/nvd/cpe/"
    timestamps: list[datetime] = []

    def response_cb(self, req: PreparedRequest) -> tuple[int, dict[str, str], str]:
        status = 200
        headers: dict[str, str] = {}
        pageLimit = 1000
        urlquery = parse_qs(urlparse(req.path_url).query)
        startIndex = int(urlquery["startIndex"][-1])
        resultsPerPage = (
            int(urlquery["resultsPerPage"][-1]) if "resultsPerPage" in urlquery else None
        )
        lastModStartDate = None
        lastModEndDate = None
        if "lastModStartDate" in urlquery:
            lastModStartDate = datetime.fromisoformat(urlquery["lastModStartDate"][-1])
            if lastModStartDate.tzinfo is None:
                lastModStartDate = lastModStartDate.replace(tzinfo=timezone.utc)
        if "lastModEndDate" in urlquery:
            lastModEndDate = datetime.fromisoformat(urlquery["lastModEndDate"][-1])
            if lastModEndDate.tzinfo is None:
                lastModEndDate = lastModEndDate.replace(tzinfo=timezone.utc)
        if resultsPerPage and pageLimit > resultsPerPage:
            pageLimit = resultsPerPage

        utcnow = datetime.utcnow()
        self.timestamps.append(utcnow)

        resp = {
            "startIndex": startIndex,
            "timestamp": utcnow.isoformat(),
        }

        products = []
        products_len = 0
        totalResults = 0
        if lastModStartDate and lastModEndDate:
            # Filter based on lastModified
            for cpe in self.cpe_examples.iterdir():
                cpe_json = json.loads(cpe.read_text())
                lastmod = cpe_json["lastModified"]
                dt = lastmod.replace(tzinfo=timezone.utc)
                if dt >= lastModStartDate and dt < lastModEndDate:
                    if totalResults >= startIndex and products_len < pageLimit:
                        products.append(cpe_json)
                        products_len += 1
                    totalResults += 1
        else:
            for cpe in self.cpe_examples.iterdir():
                if totalResults >= startIndex and products_len < pageLimit:
                    cpe_json = json.loads(cpe.read_text())
                    products.append(cpe_json)
                    products_len += 1
                totalResults += 1

        assert products_len == len(products)

        resp["totalResults"] = totalResults
        resp["products"] = products
        resp["resultsPerPage"] = products_len
        return (status, headers, json.dumps(resp))

    @responses.activate
    def test_ingest(self) -> None:
        responses.add_callback(responses.GET, re.compile(".*"), callback=self.response_cb)
        self.timestamps = []
        nvd = NVD()
        gen = nvd.products(offset=0, limit=None, last_mod_start_date=None)
        dt = cast(datetime, next(gen))
        assert dt == self.timestamps[0]

        for cpe_file in self.cpe_examples.iterdir():
            cpe = next(gen)
            cpe_json = json.loads(cpe_file.read_text())
            assert cpe == CPE.model_validate(cpe_json["cpe"])
