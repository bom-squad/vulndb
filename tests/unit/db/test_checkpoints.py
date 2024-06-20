import logging
from datetime import datetime
from datetime import timezone

from bomsquad.vulndb.db.checkpoints import Checkpoints

logger = logging.getLogger(__name__)


class TestCheckpoints:
    def test_checkpoints(self) -> None:
        cp = Checkpoints()
        utcnow = datetime.now(timezone.utc).replace(microsecond=0)

        cp.upsert("Test", utcnow)
        assert cp.last_updated("Test") == utcnow
        cp.delete("Test")
        assert cp.last_updated("Test") is None
