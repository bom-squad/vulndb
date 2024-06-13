import logging
import re
from datetime import datetime
from datetime import timezone
from pathlib import Path
from string import Template
from time import sleep
from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.parse import urlparse
from uuid import NAMESPACE_URL
from uuid import UUID
from uuid import uuid3

import pytest
import responses
from requests.models import PreparedRequest

from bomsquad.vulndb.db.checkpoints import Checkpoints
from bomsquad.vulndb.db.ingest import Ingest
from bomsquad.vulndb.db.nvddb import instance as nvddb
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE

test_root = Path(__file__).parent / "../../"

logger = logging.getLogger(__name__)


class TestIngest:
    # Test data will have bene run through ingest as part of the test_data autouse
    # fixture. These tests assert sanity checks over the import but leverage prior
    # execution.

    def test_cve_data_ingested(self, cve_examples: Path) -> None:
        assert nvddb.cve_count() == len(list(cve_examples.iterdir()))
        for cve in nvddb.cve_all():
            assert isinstance(cve, CVE)

    @pytest.mark.parametrize("update", [False, False, False, True, True])
    def test_cve_api_args(self, update: bool) -> None:
        with patch("bomsquad.vulndb.db.ingest.NVD.vulnerabilities") as vulns:
            vulns.return_value = iter([])
            Ingest.cve(update=update)
            assert vulns.call_count == 1
            args, kwargs = vulns.call_args
            assert kwargs["offset"] == 0
            cp = Checkpoints()
            if update:
                assert kwargs["last_mod_start_date"] == cp.last_updated("cve")
            else:
                assert kwargs["last_mod_start_date"] is None

    def test_cpe_data_ingested(self, cpe_examples: Path) -> None:
        assert nvddb.cpe_count() == len(list(cpe_examples.iterdir()))
        for cpe in nvddb.cpe_all():
            assert isinstance(cpe, CPE)

    @pytest.mark.parametrize("update", [False, False, False, True, True])
    def test_cpe_api_args(self, update: bool) -> None:
        with patch("bomsquad.vulndb.db.ingest.NVD.products") as products:
            products.return_value = iter([])
            Ingest.cpe(update=update)
            assert products.call_count == 1
            args, kwargs = products.call_args
            assert kwargs["offset"] == 0
            cp = Checkpoints()
            if update:
                assert kwargs["last_mod_start_date"] == cp.last_updated("cpe")
            else:
                assert kwargs["last_mod_start_date"] is None


class TestSimulateCVEIngest:
    totResults = 3
    resp_ok = Template(
        '{"resultsPerPage":1,"startIndex":${startIndex},"totalResults":${totResults},"format":"NVD_CVE","version":"2.0","timestamp":"${timestamp}","vulnerabilities":[{"cve":{"id":"${CVEid}","sourceIdentifier":"cve@mitre.org","published":"2020-02-17T13:02:54.234+00:00","lastModified":"${lastModified}","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"lorem"}],"metrics":{},"references":[]}}]}'
    )
    resp_not_found = Template(
        '{"resultsPerPage":0,"startIndex":${startIndex},"totalResults":${totResults},"format":"NVD_CVE","version":"2.0","timestamp":"${timestamp}","vulnerabilities":[]}'
    )
    cve_lastmod: dict[str, datetime] = {}

    def response_cb(self, req: PreparedRequest) -> tuple[int, dict[str, str], str]:
        status = 200
        headers: dict[str, str] = {}
        urlquery = parse_qs(urlparse(req.path_url).query)
        startIndex = int(urlquery["startIndex"][-1])
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

        params: dict[str, str] = {
            "startIndex": str(startIndex),
            "timestamp": datetime.utcnow().isoformat(),
        }

        if startIndex >= self.totResults:
            params["totResults"] = str(self.totResults)
            return (status, headers, self.resp_not_found.substitute(**params))

        if lastModStartDate and lastModEndDate:
            # Filter based on lastModified
            params["totResults"] = "0"
            found = False
            for cve, lastmod in sorted(self.cve_lastmod.items()):
                dt = lastmod.replace(tzinfo=timezone.utc)
                if dt >= lastModStartDate and dt < lastModEndDate:
                    if int(params["totResults"]) >= startIndex and not found:
                        params["CVEid"] = cve
                        params["lastModified"] = lastmod.isoformat()
                        found = True
                    params["totResults"] = str(int(params["totResults"]) + 1)

            if not found:
                return (status, headers, self.resp_not_found.substitute(**params))
        else:
            # Update the second cve (CVE-2000-1000)
            self.cve_lastmod["CVE-2000-1000"] = datetime.utcnow()
            sleep(1)

            params["CVEid"] = "CVE-2000-" + str(startIndex * 1000)
            params["lastModified"] = datetime.utcnow().isoformat()
            params["totResults"] = str(self.totResults)

            self.cve_lastmod[params["CVEid"]] = datetime.fromisoformat(params["lastModified"])

        return (status, headers, self.resp_ok.substitute(**params))

    @responses.activate
    def test_ingest(self) -> None:
        responses.add_callback(responses.GET, re.compile(".*"), callback=self.response_cb)
        Ingest.cve(update=False)
        Ingest.cve(update=True)

        dt_expect = self.cve_lastmod["CVE-2000-1000"]
        assert dt_expect
        dt_actual = nvddb.cve_by_id("CVE-2000-1000").lastModified
        assert dt_actual

        assert dt_expect.replace(microsecond=0) == dt_actual.replace(microsecond=0)

        # clean up
        for cve in self.cve_lastmod.keys():
            nvddb.delete_cve(nvddb.cve_by_id(cve))


class TestSimulateCPEIngest:
    totResults = 3
    resp_ok = Template(
        '{"resultsPerPage":1,"startIndex":${startIndex},"totalResults":${totResults},"format":"NVD_CPE","version":"2.0","timestamp":"${timestamp}","products":[{"cpe":{"deprecated":false,"cpeName":"cpe:2.3:a:famatech:advanced_port_scanner:-:*:*:*:*:*:*:*","cpeNameId":"${cpeNameId}","lastModified":"${lastModified}","created":"2007-08-23T21:05:57.937","titles":[{"title":"Famatech Advanced Port Scanner","lang":"en"}]}}]}'
    )
    resp_not_found = Template(
        '{"resultsPerPage":0,"startIndex":${startIndex},"totalResults":${totResults},"format":"NVD_CPE","version":"2.0","timestamp":"${timestamp}","products":[]}'
    )
    cpe_lastmod: dict[UUID, datetime] = {}

    def response_cb(self, req: PreparedRequest) -> tuple[int, dict[str, str], str]:
        status = 200
        headers: dict[str, str] = {}
        urlquery = parse_qs(urlparse(req.path_url).query)
        startIndex = int(urlquery["startIndex"][-1])
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

        params: dict[str, str] = {
            "startIndex": str(startIndex),
            "timestamp": datetime.utcnow().isoformat(),
        }

        if startIndex >= self.totResults:
            params["totResults"] = str(self.totResults)
            return (status, headers, self.resp_not_found.substitute(**params))

        if lastModStartDate and lastModEndDate:
            # Filter based on lastModified
            params["totResults"] = "0"
            found = False
            for cpe, lastmod in sorted(self.cpe_lastmod.items()):
                dt = lastmod.replace(tzinfo=timezone.utc)
                if dt >= lastModStartDate and dt < lastModEndDate:
                    if int(params["totResults"]) >= startIndex and not found:
                        params["cpeNameId"] = str(cpe)
                        params["lastModified"] = lastmod.isoformat()
                        found = True
                    params["totResults"] = str(int(params["totResults"]) + 1)

            if not found:
                return (status, headers, self.resp_not_found.substitute(**params))
        else:
            # Update the second cpe
            self.cpe_lastmod[uuid3(NAMESPACE_URL, "1")] = datetime.utcnow()
            sleep(1)

            params["cpeNameId"] = str(uuid3(NAMESPACE_URL, str(startIndex)))
            params["lastModified"] = datetime.utcnow().isoformat()
            params["totResults"] = str(self.totResults)

            self.cpe_lastmod[UUID(params["cpeNameId"])] = datetime.fromisoformat(
                params["lastModified"]
            )

        return (status, headers, self.resp_ok.substitute(**params))

    @responses.activate
    def test_ingest(self) -> None:
        responses.add_callback(responses.GET, re.compile(".*"), callback=self.response_cb)
        Ingest.cpe(update=False)
        Ingest.cpe(update=True)

        second_uuid = uuid3(NAMESPACE_URL, "1")
        dt_expect = self.cpe_lastmod[second_uuid]
        assert dt_expect
        dt_actual = nvddb.cpe_by_name_id(second_uuid).lastModified
        assert dt_actual

        assert dt_expect.replace(microsecond=0) == dt_actual.replace(microsecond=0)

        # clean up
        for cpe in self.cpe_lastmod.keys():
            nvddb.delete_cpe(nvddb.cpe_by_name_id(cpe))
