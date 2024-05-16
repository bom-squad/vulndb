from unittest.mock import patch

from bomsquad.vulndb.config import Config
from bomsquad.vulndb.config_resolver import ConfigResolver
from bomsquad.vulndb.config_resolver import default_config


class TestConfig:
    def test_valid_default_config(self) -> None:
        with patch.object(ConfigResolver, "resolve_config", return_value=default_config):
            assert Config.load() is not None
