import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from bomsquad.vulndb.client.nvd import CPEResultSet
from bomsquad.vulndb.client.nvd import CVEResultSet
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

    @pytest.mark.parametrize("update", [False, True])
    def test_cve_api_args(self, update: bool) -> None:
        examples = Path(__file__).parent / "examples/nvd/cve/"
        cves = [
            CVEResultSet("vulnerabilities", json.loads(path.read_text()), None)
            for path in examples.iterdir()
        ]
        with patch("bomsquad.vulndb.db.ingest.NVD.vulnerabilities") as vulns:
            vulns.return_value = iter(cves)
            with patch("bomsquad.vulndb.db.ingest.Checkpoints.upsert") as cp_upsert:
                with patch("bomsquad.vulndb.db.ingest.nvddb.upsert_cve") as upsert_cve:
                    Ingest.cve(update=update)
                    assert vulns.call_count == 1
                    args, kwargs = vulns.call_args
                    assert kwargs["offset"] == 0
                    cp = Checkpoints()
                    if update:
                        assert kwargs["last_mod_start_date"] == cp.last_updated("cve")
                    else:
                        assert kwargs["last_mod_start_date"] is None
                    args, kwargs = cp_upsert.call_args
                    assert args[0] == "cve"
                    assert args[1] == cves[0].timestamp
                    assert upsert_cve.call_count == cves[0].total_results

    def test_cpe_data_ingested(self, cpe_examples: Path) -> None:
        assert nvddb.cpe_count() == len(list(cpe_examples.iterdir()))
        for cpe in nvddb.cpe_all():
            assert isinstance(cpe, CPE)

    @pytest.mark.parametrize("update", [False, True])
    def test_cpe_api_args(self, update: bool) -> None:
        examples = Path(__file__).parent / "examples/nvd/cpe/"
        cpes = [
            CPEResultSet("products", json.loads(path.read_text()), None)
            for path in examples.iterdir()
        ]
        with patch("bomsquad.vulndb.db.ingest.NVD.products") as products:
            products.return_value = iter(cpes)
            with patch("bomsquad.vulndb.db.ingest.Checkpoints.upsert") as cp_upsert:
                with patch("bomsquad.vulndb.db.ingest.nvddb.upsert_cpe") as upsert_cpe:
                    Ingest.cpe(update=update)
                    assert products.call_count == 1
                    args, kwargs = products.call_args
                    assert kwargs["offset"] == 0
                    cp = Checkpoints()
                    if update:
                        assert kwargs["last_mod_start_date"] == cp.last_updated("cpe")
                    else:
                        assert kwargs["last_mod_start_date"] is None
                    args, kwargs = cp_upsert.call_args
                    assert args[0] == "cpe"
                    assert args[1] == cpes[0].timestamp
                    assert upsert_cpe.call_count == cpes[0].total_results
