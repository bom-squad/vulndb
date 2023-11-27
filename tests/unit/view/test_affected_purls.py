import logging
from contextlib import AbstractContextManager
from contextlib import nullcontext as does_not_raise
from typing import List

import pytest
from packageurl import PackageURL

from bomsquad.vulndb.db.error import RecordNotFoundError
from bomsquad.vulndb.view.affected_purls import AffectedPURL
from bomsquad.vulndb.view.affected_purls import query

logger = logging.getLogger(__name__)


class TestAffectedPurls:
    @pytest.mark.parametrize(
        ("id", "expectation", "expected_results"),
        [
            (
                "CVE-2023-4863",
                does_not_raise(),
                [
                    AffectedPURL(
                        purl=PackageURL(
                            type="cargo",
                            namespace=None,
                            name="libwebp-sys2",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:cargo/<0.1.8"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="cargo",
                            namespace=None,
                            name="libwebp-sys",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:cargo/<0.9.3"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="npm",
                            namespace=None,
                            name="electron",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={
                            "vers:npm/22.0.0|<22.3.24",
                            "vers:npm/24.0.0|<24.8.3",
                            "vers:npm/25.0.0|<25.8.1",
                            "vers:npm/26.0.0|<26.2.1",
                            "vers:npm/27.0.0-beta.1|<27.0.0-beta.2",
                        },
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="nuget",
                            namespace=None,
                            name="SkiaSharp",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:nuget/>=2.0.0|<2.88.6"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="golang",
                            namespace="github.com/chai2010",
                            name="webp",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:golang/>=1.0.0"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="pypi",
                            namespace=None,
                            name="pillow",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:pypi/<10.0.1"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="cargo",
                            namespace=None,
                            name="webp",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:cargo/<0.2.6"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="nuget",
                            namespace=None,
                            name="magick.net-q16-anycpu",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:nuget/>=0.0.0|<13.3.0"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="nuget",
                            namespace=None,
                            name="magick.net-q16-hdri-anycpu",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:nuget/>=0.0.0|<13.3.0"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="nuget",
                            namespace=None,
                            name="magick.net-q16-x64",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:nuget/>=0.0.0|<13.3.0"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="nuget",
                            namespace=None,
                            name="magick.net-q8-anycpu",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:nuget/>=0.0.0|<13.3.0"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="nuget",
                            namespace=None,
                            name="magick.net-q8-openmp-x64",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:nuget/>=0.0.0|<13.3.0"},
                    ),
                    AffectedPURL(
                        purl=PackageURL(
                            type="nuget",
                            namespace=None,
                            name="magick.net-q8-x64",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        ),
                        ids={"CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"},
                        versions={"vers:nuget/>=0.0.0|<13.3.0"},
                    ),
                ],
            ),
            ("CVE-1979-4242", pytest.raises(RecordNotFoundError), []),
        ],
    )
    def test_query(
        self,
        id: str,
        expectation: AbstractContextManager[Exception],
        expected_results: List[AffectedPURL],
    ) -> None:
        with expectation:
            results = query.by_id(id)
            assert len(results) == len(expected_results)
            for result in results:
                assert result in expected_results, f"{result} not found in {len(results)} results"
