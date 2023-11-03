import pytest

from bomsquad.vulndb.db.nvddb import NVDDB
from bomsquad.vulndb.db.osvdb import OSVDB


@pytest.fixture(scope="session")
def osvdb() -> OSVDB:
    return OSVDB()


@pytest.fixture(scope="session")
def nvddb() -> NVDDB:
    return NVDDB()
