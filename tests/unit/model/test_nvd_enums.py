from typing import cast

import pytest
from pytest import FixtureRequest

from bomsquad.vulndb.model.cpe import ReferenceType
from bomsquad.vulndb.model.cve import CVEStatus
from bomsquad.vulndb.model.cve import Operator
from bomsquad.vulndb.model.cve import Ordinal
from bomsquad.vulndb.model.nvd_enum import NVDEnum


class TestNVDEnums:
    @pytest.fixture(params=[ReferenceType, CVEStatus, Operator, Ordinal])
    def enum_type(self, request: FixtureRequest) -> type[NVDEnum]:
        return cast(type[NVDEnum], request.param)

    def test_enum_alt_reps(self, enum_type: type[NVDEnum]) -> None:
        for v in enum_type:
            # Generates "Example Value" for EXAMPLE_VALUE
            alt_rep = " ".join([token.lower().capitalize() for token in v.value.split("_")])
            assert isinstance(enum_type(alt_rep), enum_type)

    @pytest.mark.parametrize("bogus_value", ["BOGUS_VALUE", "Bogus Value"])
    def test_invalid_values(self, enum_type: type[NVDEnum], bogus_value: str) -> None:
        with pytest.raises(ValueError):
            enum_type(bogus_value)
