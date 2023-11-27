import logging
from typing import List
from typing import Union

from packageurl import PackageURL
from univers.versions import InvalidVersion
from univers.versions import Version

from bomsquad.vulndb.matcher.factory import VersionFactory
from bomsquad.vulndb.model.openssf import OpenSSF
from bomsquad.vulndb.model.openssf import Range

logger = logging.getLogger(__name__)

_MatchResult = Union[str, Range]


class PURLMatcher:
    @classmethod
    def simplify(cls, purl: PackageURL) -> PackageURL:
        return PackageURL(
            type=purl.type, namespace=purl.namespace, name=purl.name, subpath=purl.subpath
        )

    @classmethod
    def _in_range(cls, ecosystem: str, to_match: Version, range: Range) -> bool:
        for event in range.events:
            try:
                if event.introduced:
                    constraint = VersionFactory.for_ecosystem_version(ecosystem, event.introduced)
                    if to_match < constraint:
                        return False
                elif event.fixed:
                    constraint = VersionFactory.for_ecosystem_version(ecosystem, event.fixed)
                    if to_match >= constraint:
                        return False
                elif event.last_affected:
                    constraint = VersionFactory.for_ecosystem_version(
                        ecosystem, event.last_affected
                    )
                    if to_match >= constraint:
                        return False
                elif event.limit:
                    constraint = VersionFactory.for_ecosystem_version(ecosystem, event.limit)
                    if to_match <= constraint:
                        return False
            except InvalidVersion as iv:
                logger.error(f"Failed match due to {iv}")
                return False
        logger.info(f"[m] {to_match} matches {range}")
        return True

    @classmethod
    def _matching_criteria(cls, purl: PackageURL, osv: OpenSSF) -> List[_MatchResult]:
        results: List[_MatchResult] = []

        basic_purl = cls.simplify(purl)
        for affected in osv.affected:
            if not affected.package or affected.package.purl != basic_purl.to_string():
                continue
            if purl.version:
                to_match = VersionFactory.for_ecosystem_version(purl.type, purl.version)
                for version in affected.versions:
                    constraint = VersionFactory.for_ecosystem_version(purl.type, version)
                    if to_match == constraint:
                        results.append(version)
                        continue
                for range in affected.ranges:
                    if cls._in_range(purl.type, to_match, range):
                        results.append(range)
                        continue
            else:
                results.append("*")
        return results

    @classmethod
    def is_affected(cls, purl: PackageURL, osv: OpenSSF) -> bool:
        matching = cls._matching_criteria(purl, osv)
        return bool(matching)
