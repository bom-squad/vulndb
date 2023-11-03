import logging
import os
from importlib import resources
from pathlib import Path
from typing import cast

logger = logging.getLogger(__name__)


class ConfigResolver:
    @classmethod
    def resolve_config(cls) -> Path:
        """
        Resolve the active configuration from one of the packaged defaults, or a local configuraion
        loaded from $HOME/.watts/config.toml.
        """
        home_config = Path(f"{os.getenv('HOME')}/.vulndb/config.toml")
        if home_config.exists():
            logger.info(f"Using config from {home_config}")
            return home_config
        logger.info("Using built-in default config")
        return cast(Path, resources.files("bomsquad.vulndb").joinpath("config.toml"))
