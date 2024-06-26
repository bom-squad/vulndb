from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from bomsquad.vulndb.model.cvss20 import CVSS20
from bomsquad.vulndb.model.cvss30 import CVSS30
from bomsquad.vulndb.model.cvss31 import CVSS31
from bomsquad.vulndb.model.nvd_enum import NVDEnum


class CVEStatus(NVDEnum):
    RECEIVED = "RECEIVED"
    AWAITING_ANALYSIS = "AWAITING_ANALYSIS"
    UNDERGOING_ANALYSIS = "UNDERGOING_ANALYSIS"
    ANALYZED = "ANALYZED"
    MODIFIED = "MODIFIED"
    DEFERRED = "DEFERRED"
    REJECTED = "REJECTED"


class Ordinal(NVDEnum):
    PRIMARY = "PRIMARY"
    SECONDARY = "SECONDARY"


class CVSSv2(BaseModel):
    source: str
    type: Ordinal
    cvssData: CVSS20
    baseSeverity: str
    exploitabilityScore: float
    impactScore: float
    acInsufInfo: bool | None = None
    obtainAllPrivilege: bool | None = None
    obtainUserPrivilege: bool | None = None
    obtainOtherPrivilege: bool | None = None
    userInteractionRequired: bool | None = None


class CVSSv30(BaseModel):
    source: str
    type: Ordinal
    cvssData: CVSS30
    exploitabilityScore: float | None = None
    impactScore: float | None = None


class CVSSv31(BaseModel):
    source: str
    type: Ordinal
    cvssData: CVSS31
    exploitabilityScore: float | None = None
    impactScore: float | None


class Metrics(BaseModel):
    cvssMetricV2: list[CVSSv2] = []
    cvssMetricV30: list[CVSSv30] = []
    cvssMetricV31: list[CVSSv31] = []


class Weakness(BaseModel):
    source: str
    type: str
    description: list[dict[str, str]] = []


class Operator(NVDEnum):
    AND = "AND"
    OR = "OR"


class CPEMatch(BaseModel):
    vulnerable: bool
    criteria: str
    matchCriteriaId: UUID
    versionStartExcluding: str = "*"
    versionStartIncluding: str = "*"
    versionEndExcluding: str = "*"
    versionEndIncluding: str = "*"


class Node(BaseModel):
    operator: Operator | None = None
    negate: bool = False
    cpeMatch: list[CPEMatch] = []


class Config(BaseModel):
    operator: Operator | None = None
    negate: bool | None = False
    nodes: list[Node]


class Reference(BaseModel):
    url: str | None = None
    source: str | None = None
    tags: list[str] | None = None


class VendorComment(BaseModel):
    organization: str
    comment: str
    lastModified: datetime


class CVE(BaseModel):
    id: str
    sourceIdentifier: str
    published: datetime
    lastModified: datetime
    vulnStatus: CVEStatus
    descriptions: list[dict[str, str]] = []
    metrics: Metrics
    weaknesses: list[Weakness] = []
    configurations: list[Config] = []
    references: list[Reference] = []
    vendorComments: list[VendorComment] = []

    def description(self, language: str = "en") -> str:
        selected: str = "None"

        if self.descriptions:
            selected = self.descriptions[0]["value"]

        for desc in self.descriptions:
            if desc["lang"] == language:
                selected = desc["value"]

        return selected
