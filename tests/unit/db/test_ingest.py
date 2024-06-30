import logging
from datetime import datetime
from datetime import timezone
from pathlib import Path
from unittest.mock import patch

import pytest

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
        with patch("bomsquad.vulndb.db.ingest.NVD.vulnerabilities") as vulns:
            NullCVE = CVE.__new__(CVE)
            vulns.return_value.first_ts = datetime.now(timezone.utc)
            vulns.return_value.__iter__.return_value = iter([NullCVE, NullCVE, NullCVE])
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

                    assert cp_upsert.call_count == 1
                    assert upsert_cve.call_count == 3

    def test_cpe_data_ingested(self, cpe_examples: Path) -> None:
        assert nvddb.cpe_count() == len(list(cpe_examples.iterdir()))
        for cpe in nvddb.cpe_all():
            assert isinstance(cpe, CPE)

    @pytest.mark.parametrize("update", [False, True])
    def test_cpe_api_args(self, update: bool) -> None:
        with patch("bomsquad.vulndb.db.ingest.NVD.products") as products:
            NullCPE = CPE.__new__(CPE)
            products.return_value.first_ts = datetime.now(timezone.utc)
            products.return_value.__iter__.return_value = iter([NullCPE, NullCPE, NullCPE])
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

                    assert cp_upsert.call_count == 1
                    assert upsert_cpe.call_count == 3
