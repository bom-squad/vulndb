import json
import logging
from tempfile import NamedTemporaryFile
from typing import Generator
from typing import Sequence
from zipfile import ZipFile

import requests

from bomsquad.vulndb.model.openssf import OpenSSF

logger = logging.getLogger(__name__)


class OSV:
    OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
    ECOSYSTEMS: Sequence[str] = (
        "Go",
        "npm",
        "OSS-Fuzz",
        "PyPI",
        "RubyGems",
        "crates.io",
        "Packagist",
        "Maven",
        "NuGet",
        "Linux",
        "Debian",
        "Alpine",
        "Hex",
        "Android",
        "GitHub Actions",
        "Pub",
        "Rocky Linux",
        "AlmaLinux",
    )

    bucket: str = "osv-vulnerabilities"

    def all(self, ecosystem: str) -> Generator[OpenSSF, None, None]:
        with NamedTemporaryFile(mode="wb") as fh:
            r = requests.get(f"{self.OSV_BASE}/{ecosystem}/all.zip")
            if r.status_code != 200:
                r.raise_for_status()

            for chunk in r.iter_content(chunk_size=64 * 1024):
                fh.write(chunk)

            fh.seek(0)
            with ZipFile(fh.name, mode="r") as zfh:
                for entry in zfh.namelist():
                    with zfh.open(entry, mode="r") as content:
                        try:
                            jobj = json.load(content)
                            yield OpenSSF.parse_obj(jobj)
                        except Exception as e:
                            logger.warning(f"{entry}: {e}")
