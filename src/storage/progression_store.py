import json
import uuid
from pathlib import Path
from datetime import datetime, timezone


class ProgressionStore:
    """
    Stores:
      - attack_events.jsonl    : every accepted semantic ATT&CK mapping
      - user_sequences.jsonl   : chronological technique sequence per user
      - predictions.jsonl      : snapshot predictions per user
    """

    def __init__(self, output_dir="data/progression"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.attack_events_file = self.output_dir / "attack_events.jsonl"
        self.predictions_file = self.output_dir / "predictions.jsonl"
        self.sequences_file = self.output_dir / "user_sequences.jsonl"

        # In-memory cache for user sequences to avoid re-reading every time
        self._sequence_cache = {}

    # -----------------------------------------------------------------
    # Attack Events
    # -----------------------------------------------------------------
    def store_attack_event(self, event_record):
        """
        event_record: dict with keys:
            event_id, user_id, timestamp, source, log_type,
            mapping_id, technique_id, technique_name, tactic,
            confidence, score, raw_event
        """
        with open(self.attack_events_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_record, default=str) + "\n")

    # -----------------------------------------------------------------
    # User Sequence
    # -----------------------------------------------------------------
    def append_technique(self, user_id, technique_id, timestamp):
        """
        Append technique to user's chronological sequence.
        Returns the updated sequence list.
        """
        seq = self._load_sequence(user_id)
        seq.append({
            "technique_id": technique_id,
            "timestamp": timestamp
        })
        self._sequence_cache[user_id] = seq
        self._flush_sequence(user_id, seq)
        return [s["technique_id"] for s in seq]

    def get_sequence(self, user_id):
        """Return list of technique IDs for user."""
        seq = self._load_sequence(user_id)
        return [s["technique_id"] for s in seq]

    def _load_sequence(self, user_id):
        if user_id in self._sequence_cache:
            return self._sequence_cache[user_id]

        seq = []
        if self.sequences_file.exists():
            with open(self.sequences_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("user_id") == user_id:
                            seq = record.get("sequence", [])
                    except json.JSONDecodeError:
                        continue
        self._sequence_cache[user_id] = seq
        return seq

    def _flush_sequence(self, user_id, sequence):
        # Simple append-only line for the user.
        # In V1 we write a new line every update; readers take the last.
        record = {
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": sequence
        }
        with open(self.sequences_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    # -----------------------------------------------------------------
    # Predictions
    # -----------------------------------------------------------------
    def store_prediction(self, user_id, history, predictions):
        """
        predictions: list of (technique_id, score) from predictor
        """
        record = {
            "prediction_id": f"pred-{uuid.uuid4().hex[:8]}",
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "history": list(history),
            "predictions": [
                {"rank": i + 1, "technique_id": tid, "score": round(score, 4)}
                for i, (tid, score) in enumerate(predictions)
            ]
        }
        with open(self.predictions_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
        return record

    # -----------------------------------------------------------------
    # Reporting
    # -----------------------------------------------------------------
    def get_user_history(self, user_id):
        """Return printable history list."""
        seq = self._load_sequence(user_id)
        return seq