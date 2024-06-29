from datetime import datetime
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from pydantic import BaseModel


class SeverityType(str, Enum):
    CVSS_V2 = "CVSS_V2"
    CVSS_V3 = "CVSS_V3"


class Severity(BaseModel):
    type: SeverityType
    score: str


class Package(BaseModel):
    ecosystem: str
    name: str
    purl: Optional[str] = None


class RangeType(str, Enum):
    SEMVER = "SEMVER"
    ECOSYSTEM = "ECOSYSTEM"
    GIT = "GIT"


class Event(BaseModel):
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    last_affected: Optional[str] = None
    limit: Optional[str] = None


class Range(BaseModel):
    type: RangeType
    repo: Optional[str] = None
    events: List[Event] = []
    database_specific: Dict[Any, Any] = {}


class Affected(BaseModel):
    package: Optional[Package] = None
    severity: Optional[Severity] = None
    ranges: List[Range] = []
    versions: List[str] = []
    ecosystem_specific: Dict[Any, Any] = {}
    database_specific: Dict[Any, Any] = {}


class ReferenceType(str, Enum):
    ADVISORY = "ADVISORY"
    ARTICLE = "ARTICLE"
    DETECTION = "DETECTION"
    DISCUSSION = "DISCUSSION"
    REPORT = "REPORT"
    FIX = "FIX"
    GIT = "GIT"
    INTRODUCED = "INTRODUCED"
    PACKAGE = "PACKAGE"
    EVIDENCE = "EVIDENCE"
    WEB = "WEB"


class Reference(BaseModel):
    type: ReferenceType
    url: str


class CreditType(str, Enum):
    FINDER = "FINDER"
    REPORTER = "REPORTER"
    ANALYST = "ANALYST"
    COORDINATOR = "COORDINATOR"
    REMEDIATION_DEVELOPER = "REMEDIATION_DEVELOPER"
    REMEDIATION_REVIEWER = "REMEDIATION_REVIEWER"
    REMDIATION_VERIFIER = "REMEDIATION_VERIFIER"
    TOOL = "TOOL"
    SPONSOR = "SPONSOR"
    OTHER = "OTHER"
    UNREPORTED = "UNREPORTED"


class Credit(BaseModel):
    name: str
    contact: List[str] = []
    type: CreditType = CreditType.UNREPORTED


class OpenSSF(BaseModel):
    schema_version: Optional[str] = None
    id: str
    published: Optional[datetime] = None
    modified: datetime
    withdrawn: Optional[datetime] = None
    aliases: List[str] = []
    related: List[str] = []
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: List[Severity] = []
    affected: List[Affected] = []
    references: List[Reference] = []
    credits: List[Credit] = []
    database_specific: Dict[Any, Any] = {}
