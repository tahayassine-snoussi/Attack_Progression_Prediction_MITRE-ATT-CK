import json
from pathlib import Path


class OffsetStore:

    def __init__(self, path):
        self.path = Path(path)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        if not self.path.exists():
            self._save({})

        self.offsets = self._load()

    def _load(self):
        with open(
            self.path,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    def _save(self, data):
        temp_path = self.path.with_suffix(".tmp")

        with open(
            temp_path,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                data,
                file,
                indent=4
            )

        temp_path.replace(self.path)

    def get(self, source_id):
        return self.offsets.get(
            source_id,
            {
                "offset": 0,
                "inode": None
            }
        )

    def set(self, source_id, offset, inode):
        self.offsets[source_id] = {
            "offset": offset,
            "inode": inode
        }

        self._save(self.offsets)

    def reset(self, source_id):
        self.offsets[source_id] = {
            "offset": 0,
            "inode": None
        }

        self._save(self.offsets)