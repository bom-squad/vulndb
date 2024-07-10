import json
import logging
import re
from datetime import datetime
from datetime import timezone
from pathlib import Path
from urllib.parse import parse_qs
from urllib.parse import urlparse

import responses
from requests.models import PreparedRequest

from bomsquad.vulndb.client.nvd import NVD
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE

logger = logging.getLogger(__name__)


class TestVulnerabilities:
    example_file = Path(__file__).parent / "examples/nvd/cve.json"
    cve_examples = json.loads(example_file.read_text())
    timestamps: list[datetime] = []

    def response_cb(self, req: PreparedRequest) -> tuple[int, dict[str, str], str]:
        status = 200
        headers: dict[str, str] = {}
        pageLimit = 5
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
            "version": "2.0",
            "format": "NVD_CVE",
            "startIndex": startIndex,
            "timestamp": utcnow.isoformat(),
        }

        vulns = []
        vulns_len = 0
        totalResults = 0
        if lastModStartDate and lastModEndDate:
            # Filter based on lastModified
            for cve in self.cve_examples:
                lastmod = datetime.fromisoformat(cve["cve"]["lastModified"])
                dt = lastmod.replace(tzinfo=timezone.utc)
                if dt >= lastModStartDate and dt < lastModEndDate:
                    if totalResults >= startIndex and vulns_len < pageLimit:
                        vulns.append(cve)
                        vulns_len += 1
                    totalResults += 1
        else:
            for cve in self.cve_examples:
                if totalResults >= startIndex and vulns_len < pageLimit:
                    vulns.append(cve)
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
        expected_cves = iter(self.cve_examples)

        result_count = 0
        for resultset in gen:
            assert resultset.timestamp == self.timestamps[result_count]
            result_count += 1
            for cve in resultset:
                expected_cve = CVE.model_validate(next(expected_cves)["cve"])
                assert cve == expected_cve

    @responses.activate
    def test_ingest_update(self) -> None:
        responses.add_callback(responses.GET, re.compile(".*"), callback=self.response_cb)
        self.timestamps = []
        nvd = NVD()
        lastmod = datetime.fromisoformat("2018-10-12T21:29:34.903")
        gen = nvd.vulnerabilities(offset=0, limit=None, last_mod_start_date=lastmod)
        expected_cves = iter(self.cve_examples)

        result_count = 0
        for resultset in gen:
            assert resultset.timestamp == self.timestamps[result_count]
            result_count += 1
            for cve in resultset:
                while True:
                    expected_cve = CVE.model_validate(next(expected_cves)["cve"])
                    if expected_cve.lastModified >= lastmod:
                        assert cve == expected_cve
                        break


class TestProducts:
    example_file = Path(__file__).parent / "examples/nvd/cpe.json"
    cpe_examples = json.loads(example_file.read_text())
    timestamps: list[datetime] = []

    def response_cb(self, req: PreparedRequest) -> tuple[int, dict[str, str], str]:
        status = 200
        headers: dict[str, str] = {}
        pageLimit = 5
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
            "version": "2.0",
            "format": "NVD_CPE",
            "startIndex": startIndex,
            "timestamp": utcnow.isoformat(),
        }

        products = []
        products_len = 0
        totalResults = 0
        if lastModStartDate and lastModEndDate:
            # Filter based on lastModified
            for cpe in self.cpe_examples:
                lastmod = datetime.fromisoformat(cpe["cpe"]["lastModified"])
                dt = lastmod.replace(tzinfo=timezone.utc)
                if dt >= lastModStartDate and dt < lastModEndDate:
                    if totalResults >= startIndex and products_len < pageLimit:
                        products.append(cpe)
                        products_len += 1
                    totalResults += 1
        else:
            for cpe in self.cpe_examples:
                if totalResults >= startIndex and products_len < pageLimit:
                    products.append(cpe)
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
        expected_cpes = iter(self.cpe_examples)

        result_count = 0
        for resultset in gen:
            assert resultset.timestamp == self.timestamps[result_count]
            result_count += 1
            for cpe in resultset:
                expected_cpe = CPE.model_validate(next(expected_cpes)["cpe"])
                assert cpe == expected_cpe

    @responses.activate
    def test_ingest_update(self) -> None:
        responses.add_callback(responses.GET, re.compile(".*"), callback=self.response_cb)
        self.timestamps = []
        nvd = NVD()
        lastmod = datetime.fromisoformat("2018-10-12T21:29:34.903")
        gen = nvd.products(offset=0, limit=None, last_mod_start_date=lastmod)
        expected_cpes = iter(self.cpe_examples)

        result_count = 0
        for resultset in gen:
            assert resultset.timestamp == self.timestamps[result_count]
            result_count += 1
            for cpe in resultset:
                while True:
                    expected_cpe = CPE.model_validate(next(expected_cpes)["cpe"])
                    if expected_cpe.lastModified >= lastmod:
                        assert cpe == expected_cpe
                        break
