import logging
from contextlib import AbstractContextManager
from contextlib import nullcontext as does_not_raise
from pathlib import Path
from uuid import UUID

import pytest
from tests.factory import CPEFactory
from tests.factory import CPEReferenceFactory
from tests.factory import CVEFactory
from tests.factory import CVEReferenceFactory

from bomsquad.vulndb.db.error import RecordNotFoundError
from bomsquad.vulndb.db.nvddb import instance as nvddb

logger = logging.getLogger(__name__)


class TestNVDDB:
    @pytest.mark.parametrize(
        ("id", "expectation"),
        [
            ("CVE-2023-4863", does_not_raise()),
            ("CVE-1968-4242", pytest.raises(RecordNotFoundError)),
        ],
    )
    def test_cve_by_id(self, id: str, expectation: AbstractContextManager[Exception]) -> None:
        with expectation:
            cve = nvddb.cve_by_id(id)
            assert cve.id == id

    def test_upsert_new_cve(self) -> None:
        new_cve = CVEFactory.build()
        try:
            existing = nvddb.cve_by_id(new_cve.id)
            assert False, f"Pre-existing record for {existing.id}"
        except RecordNotFoundError:
            nvddb.upsert_cve(new_cve)
            assert nvddb.cve_by_id(new_cve.id).id == new_cve.id
            nvddb.delete_cve(new_cve)

    def test_upsert_update_cve(self) -> None:
        existing_cve = list(nvddb.cve_all())[0]
        new_reference = CVEReferenceFactory.build()
        existing_cve.references.append(new_reference)
        nvddb.upsert_cve(existing_cve)
        assert new_reference in nvddb.cve_by_id(existing_cve.id).references

    def test_cve_count(self, cve_examples: Path) -> None:
        assert nvddb.cve_count() == len(list(cve_examples.iterdir()))

    def test_cve_all(self) -> None:
        for cve in nvddb.cve_all():
            assert cve
            assert cve.id

    def test_cve_last_modified(self) -> None:
        last_modified = nvddb.cve_last_modified()
        assert last_modified
        assert last_modified.isoformat() == "2023-10-28T19:15:38.643000-04:00"

    @pytest.mark.parametrize(
        ("id", "expectation"),
        [
            (UUID("f8b9bd61-3da4-4cbd-9185-f94c860ad3ba"), does_not_raise()),
            (UUID("a48546fd-79f4-8675-ab0d-f93847a7a4b7"), pytest.raises(RecordNotFoundError)),
        ],
    )
    def test_cpe_by_name_id(self, id: UUID, expectation: AbstractContextManager[Exception]) -> None:
        with expectation:
            cpe = nvddb.cpe_by_name_id(id)
            assert cpe.cpeNameId == id

    def test_upsert_new_cpe(self) -> None:
        new_cpe = CPEFactory.build()
        try:
            existing = nvddb.cpe_by_name_id(new_cpe.cpeNameId)
            assert False, f"Pre-existing record for {existing.cpeNameId}"
        except RecordNotFoundError:
            nvddb.upsert_cpe(new_cpe)
            assert nvddb.cpe_by_name_id(new_cpe.cpeNameId).cpeNameId == new_cpe.cpeNameId
            nvddb.delete_cpe(new_cpe)

    def test_upsert_update_cpe(self) -> None:
        existing_cpe = list(nvddb.cpe_all())[0]
        new_reference = CPEReferenceFactory.build()
        existing_cpe.refs.append(new_reference)
        nvddb.upsert_cpe(existing_cpe)
        assert new_reference in nvddb.cpe_by_name_id(existing_cpe.cpeNameId).refs

    def test_cpe_count(self, cpe_examples: Path) -> None:
        assert nvddb.cpe_count() == len(list(cpe_examples.iterdir()))

    def test_cpe_all(self) -> None:
        for cpe in nvddb.cpe_all():
            assert cpe
            assert cpe.cpeName
            assert cpe.cpeNameId

    def test_cpe_last_modified(self) -> None:
        last_modified = nvddb.cpe_last_modified()
        assert last_modified
        assert last_modified.isoformat() == "2023-10-31T15:21:10.153000-04:00"
