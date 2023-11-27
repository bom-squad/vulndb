from contextlib import AbstractContextManager
from contextlib import nullcontext as does_not_raise

import pytest

from bomsquad.vulndb.matcher.factory import VersionFactory


class TestVersionFactory:
    @pytest.mark.parametrize(
        ("ecosystem", "spec", "expectation"),
        [
            ("npm", "1.0", does_not_raise()),
            ("pypi", "42.0.3", does_not_raise()),
            ("maven", "1.0", does_not_raise()),
            ("go", "1.0", does_not_raise()),
            ("nuget", "1.0", does_not_raise()),
            ("npm", "1.0", does_not_raise()),
            ("cargo", "1.0", does_not_raise()),
            ("void", "1.0", pytest.raises(ValueError)),
            ("pypi", "whiskeytango", pytest.raises(ValueError)),
        ],
    )
    def test_for_ecosystem_version(
        self, ecosystem: str, spec: str, expectation: AbstractContextManager[Exception]
    ) -> None:
        with expectation:
            assert VersionFactory.for_ecosystem_version(ecosystem, spec)
