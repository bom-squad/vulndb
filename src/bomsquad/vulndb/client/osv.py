import json
import logging
from functools import cached_property
from tempfile import NamedTemporaryFile
from typing import Generator
from typing import Optional
from typing import Sequence
from zipfile import ZipFile

from google.cloud import storage

from bomsquad.vulndb.model.openssf import OpenSSF

logger = logging.getLogger(__name__)


class OSV:
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

    @cached_property
    def _gcs(self) -> storage.Client:
        return storage.Client()

    def all(self, ecosystem: str) -> Generator[OpenSSF, None, None]:
        gcs = self._gcs
        with NamedTemporaryFile(mode="wb") as fh:
            blob = gcs.bucket(self.bucket).blob(f"{ecosystem}/all.zip")
            blob.download_to_file(fh)
            fh.seek(0)
            with ZipFile(fh.name, mode="r") as zfh:
                for entry in zfh.namelist():
                    with zfh.open(entry, mode="r") as content:
                        try:
                            jobj = json.load(content)
                            yield OpenSSF.parse_obj(jobj)
                        except Exception as e:
                            logger.warning(f"{blob.name}: {e}")

    def get(
        self, ecosystem: str, offset: int = 0, limit: Optional[int] = None
    ) -> Generator[OpenSSF, None, None]:
        gcs = self._gcs
        for blob in gcs.list_blobs(self.bucket, prefix=ecosystem):
            try:
                jobj = json.loads(blob.download_as_string())
                yield OpenSSF.parse_obj(jobj)
            except Exception as e:
                logger.warning(f"{blob.name}: {e}")
