import logging
from contextlib import AbstractContextManager
from contextlib import nullcontext as does_not_raise

import pytest
from packageurl import PackageURL

from bomsquad.vulndb.matcher.factory import VersionRangeFactory
from bomsquad.vulndb.model.openssf import Event
from bomsquad.vulndb.model.openssf import Range
from bomsquad.vulndb.model.openssf import RangeType

logger = logging.getLogger(__name__)


class TestVersionRangeFactory:
    @pytest.mark.parametrize(
        ("purl", "affected_range", "expectation"),
        [
            (
                "pkg:PyPI/cryptography",
                Range(
                    type=RangeType.SEMVER,
                    events=[Event(introduced="37.0.0"), Event(last_affected="38.0.3")],
                ),
                does_not_raise(),
            ),
            (
                "pkg:PyPI/cryptography",
                Range(
                    type=RangeType.SEMVER, events=[Event(introduced="5.0.3"), Event(limit="38.0")]
                ),
                does_not_raise(),
            ),
            (
                "pkg:PyPI/cryptography",
                Range(
                    type=RangeType.SEMVER,
                    events=[
                        Event(introduced="38.0.3"),
                    ],
                ),
                does_not_raise(),
            ),
            (
                "pkg:void/idkfa]",
                Range(
                    type=RangeType.SEMVER,
                    events=[Event(introduced="6.8"), Event(last_affected="8.4")],
                ),
                pytest.raises(ValueError),
            ),
            ("bogon", Range(type=RangeType.GIT, events=[]), pytest.raises(ValueError)),
        ],
    )
    def test_for_osv_affected_package_range(
        self, purl: str, affected_range: Range, expectation: AbstractContextManager[Exception]
    ) -> None:
        with expectation:
            assert VersionRangeFactory.for_osv_affected_package_range(
                PackageURL.from_string(purl), affected_range
            )
