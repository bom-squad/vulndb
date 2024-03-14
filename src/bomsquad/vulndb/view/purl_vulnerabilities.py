from __future__ import annotations

import logging
from dataclasses import dataclass

from packageurl import PackageURL

from bomsquad.vulndb.db.osvdb import instance as osvdb
from bomsquad.vulndb.matcher.purl import PURLMatcher
from bomsquad.vulndb.model.spec import Spec

logger = logging.getLogger(__name__)


@dataclass
class PURLVulnerability:
    id: str
    aliases: list[str]
    affected_versions: list[str]
    affected_version_ranges: list[str]


class _Query:
    def by_purl(self, target: str) -> list[PURLVulnerability]:
        purl = PackageURL.from_string(target)
        results: list[PURLVulnerability] = []

        basic_purl = PURLMatcher.simplify(purl)
        for osv in osvdb.find_by_purl(basic_purl):
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


query = _Query()
