import json
from pathlib import Path


class SourceRegistry:

    def __init__(self, config_path):
        self.config_path = Path(config_path)
        self.sources = self._load()

    def _load(self):
        with open(
            self.config_path,
            "r",
            encoding="utf-8"
        ) as file:
            config = json.load(file)

        return config.get("sources", [])

    def get_sources(self):
        return self.sources