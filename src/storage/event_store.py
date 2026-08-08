import json
from pathlib import Path


class EventStore:

    def __init__(self, output_dir="data/events"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

    def store_events(self, events, log_type):

        output_file = (
            self.output_dir /
            f"{log_type}.jsonl"
        )

        with open(
            output_file,
            "a",
            encoding="utf-8"
        ) as f:

            for event in events:

                f.write(
                    json.dumps(event)
                    + "\n"
                )