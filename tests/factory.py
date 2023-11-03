from polyfactory.factories.pydantic_factory import ModelFactory

from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cpe import Reference as CPEReference
from bomsquad.vulndb.model.cve import CVE
from bomsquad.vulndb.model.cve import Reference as CVEReference
from bomsquad.vulndb.model.openssf import Credit
from bomsquad.vulndb.model.openssf import OpenSSF


class CVEFactory(ModelFactory[CVE]):
    __model__ = CVE


class CVEReferenceFactory(ModelFactory[CVEReference]):
    __model__ = CVEReference


class CPEFactory(ModelFactory[CPE]):
    __model__ = CPE


class CPEReferenceFactory(ModelFactory[CPEReference]):
    __model__ = CPEReference


class OpenSSFFactory(ModelFactory[OpenSSF]):
    __model__ = OpenSSF


class CreditFactory(ModelFactory[Credit]):
    __model__ = Credit
