import logging
from dataclasses import dataclass
from typing import List

from packageurl import PackageURL

from bomsquad.vulndb.db.osvdb import instance as osvdb
from bomsquad.vulndb.matcher.purl import PURLMatcher
from bomsquad.vulndb.model.spec import Spec

logger = logging.getLogger(__name__)


@dataclass
class PURLVulnerability:
    id: str
    aliases: List[str]
    affected_versions: List[str]
    affected_version_ranges: List[str]


class _Query:
    def by_purl(self, target: str) -> List[PURLVulnerability]:
        purl = PackageURL.from_string(target)
        results: List[PURLVulnerability] = []

        basic_purl = PURLMatcher.simplify(purl)
        for osv, data in osvdb.find_by_purl(basic_purl):
            if PURLMatcher.is_affected(purl, osv) is False:
                continue

            vuln = PURLVulnerability(osv.id, osv.aliases, [], [])

            for affected in osv.affected:
                if affected.package and affected.package.purl == basic_purl.to_string():
                    for version in affected.versions:
                        vuln.affected_versions.append(version)
                    for range in affected.ranges:
                        vuln.affected_version_ranges.append(Spec.range(range))

            results.append(vuln)

        return results

    def by_purl_json(self, target: str) -> List[PURLVulnerability]:
        purl = PackageURL.from_string(target)
        results: List[PURLVulnerability] = []

        basic_purl = PURLMatcher.simplify(purl)
        for osv, data in osvdb.find_by_purl(basic_purl):
            if PURLMatcher.is_affected(purl, osv) is False:
                continue

            results.append(data)

        return results

query = _Query()
