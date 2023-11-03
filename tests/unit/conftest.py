import json
import logging
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest

from bomsquad.vulndb.client.osv import OSV
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE
from bomsquad.vulndb.model.openssf import OpenSSF

unit_root = Path(__file__).parent

# Patch config file resolution to point at the unit test configuration. Note that
# any importing any singletons that trigger loading database connections needs to
# be defered until after this patch, hence several fixtures below defer their
# imports.
with patch(
    "bomsquad.vulndb.config_resolver.ConfigResolver.resolve_config",
    return_value=unit_root / "config.toml",
):
    from bomsquad.vulndb.config import instance as config

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session", autouse=True)
def test_database() -> Generator[None, None, None]:
    from bomsquad.vulndb.db.connection import pool
    from bomsquad.vulndb.db.manager import instance as dbm

    logger.info(f"Creating test database instance {config.database}")
    dbm.create()
    dbm.create_tables()
    dbm.create_user()
    try:
        yield
    finally:
        logger.info("Shutting down active connection pool")
        pool.close()
        logger.info("Dropping test database instance")
        dbm.drop()


@pytest.fixture(scope="session")
def cve_examples() -> Path:
    return unit_root / "../example/nvd/cve"


@pytest.fixture(scope="session")
def cpe_examples() -> Path:
    return unit_root / "../example/nvd/cpe"


@pytest.fixture(scope="session")
def osv_examples() -> Path:
    return unit_root / "../example/osv"


@pytest.fixture(scope="session", autouse=True)
def test_data(
    cve_examples: Path, cpe_examples: Path, osv_examples: Path, test_database: None
) -> None:
    from bomsquad.vulndb.db.ingest import Ingest

    with patch("bomsquad.vulndb.db.ingest.NVD.vulnerabilities") as vulns:
        vulns.return_value.__iter__.return_value = [
            CVE.model_validate(json.loads(path.read_text())) for path in cve_examples.iterdir()
        ]
        Ingest.cve()

    with patch("bomsquad.vulndb.db.ingest.NVD.products") as products:
        products.return_value.__iter__.return_value = [
            CPE.model_validate(json.loads(path.read_text())) for path in cpe_examples.iterdir()
        ]
        Ingest.cpe()

    saved_ecosystems = OSV.ECOSYSTEMS
    OSV.ECOSYSTEMS = [ecosystem.name for ecosystem in osv_examples.iterdir()]
    try:
        with patch(
            "bomsquad.vulndb.db.ingest.OSV.all",
            new=lambda _cls, ecosystem: [
                OpenSSF.model_validate(json.loads(path.read_text()))
                for path in (osv_examples / ecosystem).iterdir()
            ],
        ):
            Ingest.all_osv()
    finally:
        OSV.ECOSYSTEMS = saved_ecosystems
