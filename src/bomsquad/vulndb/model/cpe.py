from datetime import datetime
from typing import List
from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from bomsquad.vulndb.model.nvd_enum import NVDEnum


class Title(BaseModel):
    lang: str
    title: str


class ReferenceType(NVDEnum):
    ADVISORY = "ADVISORY"
    CHANGE_LOG = "CHANGE_LOG"
    PRODUCT = "PRODUCT"
    PROJECT = "PROJECT"
    VENDOR = "VENDOR"
    VERSION = "VERSION"


class Reference(BaseModel):
    type: Optional[ReferenceType] = None
    ref: str


class CPERef(BaseModel):
    cpeName: str
    cpeNameId: UUID


class CPE(BaseModel):
    deprecated: bool
    cpeName: str
    cpeNameId: UUID
    lastModified: datetime
    created: datetime
    titles: List[Title] = []
    refs: List[Reference] = []
    deprecatedBy: List[CPERef] = []
    deprecates: List[CPERef] = []
