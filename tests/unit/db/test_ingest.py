import logging
from datetime import datetime
from datetime import timezone
from pathlib import Path
from unittest.mock import patch

import pytest

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

    @pytest.mark.parametrize(
        ("offset", "last_mod_start_date"),
        [
            (None, None),
            (0, None),
            (42, None),
            (None, datetime.now(timezone.utc)),
            (42, datetime.now(timezone.utc)),
        ],
    )
    def test_cve_api_args(self, offset: int | None, last_mod_start_date: datetime | None) -> None:
        with patch("bomsquad.vulndb.db.ingest.NVD.vulnerabilities") as vulns:
            if offset:
                Ingest.cve(offset, last_mod_start_date=last_mod_start_date)
            else:
                Ingest.cve(last_mod_start_date=last_mod_start_date)
            assert vulns.call_count == 1
            args, kwargs = vulns.call_args
            if offset:
                assert args[0] == offset
            else:
                assert args[0] == 0
            assert kwargs["last_mod_start_date"] == last_mod_start_date

    def test_cpe_data_ingested(self, cpe_examples: Path) -> None:
        assert nvddb.cpe_count() == len(list(cpe_examples.iterdir()))
        for cpe in nvddb.cpe_all():
            assert isinstance(cpe, CPE)

    @pytest.mark.parametrize(
        ("offset", "last_mod_start_date"),
        [
            (None, None),
            (0, None),
            (42, None),
            (None, datetime.now(timezone.utc)),
            (42, datetime.now(timezone.utc)),
        ],
    )
    def test_cpe_api_args(self, offset: int | None, last_mod_start_date: datetime | None) -> None:
        with patch("bomsquad.vulndb.db.ingest.NVD.products") as products:
            if offset:
                Ingest.cpe(offset, last_mod_start_date=last_mod_start_date)
            else:
                Ingest.cpe(last_mod_start_date=last_mod_start_date)
            assert products.call_count == 1
            args, kwargs = products.call_args
            if offset:
                assert args[0] == offset
            else:
                assert args[0] == 0
            assert kwargs["last_mod_start_date"] == last_mod_start_date
