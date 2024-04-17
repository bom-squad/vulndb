import logging
from contextlib import AbstractContextManager
from contextlib import nullcontext as does_not_raise
from typing import List

import pytest

from bomsquad.vulndb.view.purl_vulnerabilities import PURLVulnerability
from bomsquad.vulndb.view.purl_vulnerabilities import query

logger = logging.getLogger(__name__)


class TestPURLVulnerabilities:
    @pytest.mark.parametrize(
        ("id", "expectation", "expected_results"),
        [
            (
                "pkg:npm/electron",
                does_not_raise(),
                [
                    PURLVulnerability(
                        id="GHSA-j7hp-h8jx-5ppr",
                        aliases=["CVE-2023-4863"],
                        affected_versions=[],
                        affected_version_ranges=[
                            ">= 22.0.0 and < 22.3.24",
                            ">= 24.0.0 and < 24.8.3",
                            ">= 25.0.0 and < 25.8.1",
                            ">= 26.0.0 and < 26.2.1",
                            ">= 27.0.0-beta.1 and < 27.0.0-beta.2",
                        ],
                    )
                ],
            ),
            ("pkg:pypi/nosuchpackage", does_not_raise(), []),
            ("malformed_purl", pytest.raises(ValueError), []),
        ],
    )
    def test_query(
        self,
        id: str,
        expectation: AbstractContextManager[Exception],
        expected_results: List[PURLVulnerability],
    ) -> None:
        with expectation:
            results = query.by_purl(id)
            assert len(results) == len(expected_results)
            for result in results:
                assert result in expected_results
