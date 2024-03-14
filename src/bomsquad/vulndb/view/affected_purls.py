import logging
from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Set

from packageurl import PackageURL
from univers.version_range import VersionRange

from bomsquad.vulndb.db.osvdb import instance as osvdb
from bomsquad.vulndb.matcher.factory import VersionRangeFactory

logger = logging.getLogger(__name__)


@dataclass
class AffectedPURL:
    purl: PackageURL
    ids: Set[str]
    versions: Set[str]

    def add_id(self, id: str) -> None:
        self.ids.add(id)

    def add_version(self, version: VersionRange) -> None:
        self.versions.add(version.to_string())

    @classmethod
    def for_purl(self, purl: str) -> "AffectedPURL":
        return AffectedPURL(PackageURL.from_string(purl), set(), set())


class _Query:
    def by_id(self, id: str) -> List[AffectedPURL]:
        by_purl: Dict[str, AffectedPURL] = {}
        for osv in osvdb.find_by_id_or_alias(id):
            logger.info(f"osv {osv.id}")
            for affected in osv.affected:
                if affected.package and affected.package.purl:
                    entry: AffectedPURL
                    if affected.package.purl not in by_purl.keys():
                        entry = AffectedPURL.for_purl(affected.package.purl)
                        by_purl[affected.package.purl] = entry
                    else:
                        entry = by_purl[affected.package.purl]
                    entry.add_id(osv.id)
                    for alias in osv.aliases:
                        entry.add_id(alias)

                    for range in affected.ranges:
                        entry.add_version(
                            VersionRangeFactory.for_osv_affected_package_range(entry.purl, range)
                        )

        return list(by_purl.values())


query = _Query()
