from contextlib import AbstractContextManager
from contextlib import nullcontext as does_not_raise

import pytest
from packageurl import PackageURL

from bomsquad.vulndb.db.osvdb import instance as osvdb
from bomsquad.vulndb.matcher.purl import PURLMatcher
from bomsquad.vulndb.model.openssf import OpenSSF


class TestPURLMatcher:
    @pytest.fixture()
    def osv(self) -> OpenSSF:
        return list(osvdb.find_by_id_or_alias("CVE-2023-4863"))[0]

    @pytest.mark.parametrize(
        ("purl", "expectation", "expected_result"),
        [
            ("pkg:npm/electron@42.2.2", does_not_raise(), False),
            ("pkg:npm/electron@22.2.1", does_not_raise(), True),
            ("pkg:PyPI/cryptography", does_not_raise(), False),
        ],
    )
    def test_is_affected(
        self,
        purl: str,
        expectation: AbstractContextManager[Exception],
        expected_result: bool,
        osv: OpenSSF,
    ) -> None:
        with expectation:
            assert (
                PURLMatcher.is_affected(PackageURL.from_string(purl), osv) == expected_result
            ), f"{purl} should not match {osv.id}"
