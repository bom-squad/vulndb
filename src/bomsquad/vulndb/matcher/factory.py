import logging

from packageurl import PackageURL
from univers.version_range import NugetVersionRange
from univers.version_range import VersionRange
from univers.versions import GolangVersion
from univers.versions import MavenVersion
from univers.versions import NugetVersion
from univers.versions import PypiVersion
from univers.versions import SemverVersion
from univers.versions import Version

from bomsquad.vulndb.model.openssf import Range

logger = logging.getLogger(__name__)


class VersionFactory:
    @classmethod
    def for_ecosystem_version(cls, ecosystem: str, spec: str) -> Version:
        if ecosystem == "pypi":
            return PypiVersion(spec)
        elif ecosystem == "maven":
            return MavenVersion(spec)
        elif ecosystem == "go" or ecosystem == "golang":
            return GolangVersion(spec)
        elif ecosystem == "nuget":
            return NugetVersion(spec)
        elif ecosystem == "cargo":
            return SemverVersion(spec)
        raise ValueError("Unknown ecosystem")


class VersionRangeFactory:
    @classmethod
    def _range_for(cls, type: str, low: str, high: str, op: str) -> str:
        if type == "nuget":
            return f"[{low},{high}{']' if op == '>=' else ')'}"
        else:
            return f"{low},{op}{high}"

    @classmethod
    def for_osv_affected_package_range(
        cls, purl: PackageURL, affected_range: Range
    ) -> VersionRange:
        low: str
        high: str = "*"
        high_operator: str = ""
        for event in affected_range.events:
            if event.introduced:
                low = event.introduced
            elif event.fixed:
                high = event.fixed
                high_operator = "<"
            elif event.limit:
                high = event.limit
                high_operator = "<"
            elif event.last_affected:
                high = event.last_affected
                high_operator = "<="

        # .NET has a strange syntax. Maybe there's a cleaner way to do this with univers, but on
        # demo deadline, this will work.
        if purl.type == "nuget":
            spec = f"[{low},{high}{']' if high_operator == '>=' else ')'}"
            return NugetVersionRange.from_native(
                f"[{low},{high}{']' if high_operator == '>=' else ')'}"
            )

        low_str = f"{low}," if low != "0" else ""
        spec = f"vers:{purl.type}/{low_str}{high_operator}{high}"
        return VersionRange.from_string(spec)
