from unittest.mock import patch

from bomsquad.vulndb.config_resolver import ConfigResolver
from bomsquad.vulndb.config_resolver import default_config


def test_valid_default_config() -> None:
    with patch.object(ConfigResolver, "resolve_config", return_value=default_config):
        from bomsquad.vulndb.config import instance as config

        assert config.load() is not None
