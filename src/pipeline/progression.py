from datetime import datetime, timezone

from storage.progression_store import ProgressionStore
from prediction.predictor import AttackPredictor


DEFAULT_USER_ID = "lab_user"


class ProgressionIntegration:
    """
    Glue layer between semantic mappings and the prediction model.
    """

    def __init__(self,
                 predictor=None,
                 progression_store=None,
                 default_user=DEFAULT_USER_ID):
        self.default_user = default_user
        self.store = progression_store or ProgressionStore()
        self.predictor = predictor or AttackPredictor()

    # -----------------------------------------------------------------
    # Zeek
    # -----------------------------------------------------------------
    def process_zeek_semantic_results(self, semantic_results, log_type):
        """
        semantic_results: dict with key "semantic_results" -> list of
            {"event": <normalized>, "matches": [<match>, ...]}
        """
        results = semantic_results.get("semantic_results", [])
        match_count = 0

        for item in results:
            event = item.get("event", {})
            matches = item.get("matches", [])

            for match in matches:
                match_count += 1
                self._handle_match(
                    source="Zeek",
                    log_type=log_type,
                    event=event,
                    match=match
                )

        return match_count

    # -----------------------------------------------------------------
    # Wazuh
    # -----------------------------------------------------------------
    def process_wazuh_mapped_events(self, mapped_events):
        """
        mapped_events: list from map_wazuh_events()
        """
        match_count = 0

        for item in mapped_events:
            # Skip correlation-only results (different structure)
            if item.get("correlation") is True:
                continue

            event = item.get("event", {})
            mappings = item.get("mappings", [])

            for match in mappings:
                match_count += 1
                self._handle_match(
                    source="Wazuh",
                    log_type=event.get("log_type", "unknown"),
                    event=event,
                    match=match
                )

        return match_count

    # -----------------------------------------------------------------
    # Common handler
    # -----------------------------------------------------------------
    def _handle_match(self, source, log_type, event, match):
        # Extract fields safely
        technique_id = None
        technique_name = None
        tactic = None
        mapping_id = None
        confidence = 0.0
        score = 0.0

        if isinstance(match, dict):
            # Zeek format
            technique_id = match.get("technique_id")
            technique_name = match.get("technique_name")
            tactic = match.get("tactic")
            mapping_id = match.get("mapping_id")
            confidence = match.get("confidence_score", 0.0)
            score = match.get("score", 0.0)

            # Wazuh format (nested under "technique")
            if not technique_id and "technique" in match:
                tech = match["technique"]
                if isinstance(tech, dict):
                    technique_id = tech.get("technique_id")
                    technique_name = tech.get("technique_name")
                    tactic = tech.get("tactic")

            if not mapping_id:
                mapping_id = match.get("mapping_id", "UNKNOWN")

            if not confidence and "confidence_score" in match:
                confidence = float(match["confidence_score"])

            if not score and "match" in match:
                score = float(match["match"].get("score", 0.0))

        # Timestamp from event
        timestamp = event.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        # Build attack event record
        attack_event = {
            "event_id": event.get("id") or f"evt-{datetime.now(timezone.utc).timestamp()}",
            "user_id": self.default_user,
            "timestamp": timestamp,
            "source": source,
            "log_type": log_type,
            "mapping_id": mapping_id,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "confidence": confidence,
            "score": score,
            "raw_event": event
        }

        # Persist attack event
        self.store.store_attack_event(attack_event)

        print(f"[PROGRESSION] Stored attack event: {technique_id} ({technique_name}) "
              f"from {source}/{log_type} for {self.default_user}")

        # Vocabulary filter
        vocab = set(self.predictor.vocab) if self.predictor.vocab else set()
        if technique_id and technique_id in vocab:
            # Append to sequence and predict
            full_sequence = self.store.append_technique(
                self.default_user,
                technique_id,
                timestamp
            )

            print(f"[PROGRESSION] User sequence: {' -> '.join(full_sequence)}")

            # Trigger prediction (minimum length = 1, per training script)
            if len(full_sequence) >= 1:
                try:
                    preds = self.predictor.predict(full_sequence, top_k=5)
                    if preds:
                        pred_record = self.store.store_prediction(
                            self.default_user,
                            full_sequence,
                            preds
                        )
                        print(f"[PROGRESSION] Prediction stored: {pred_record['prediction_id']}")
                        self._print_prediction(preds)
                except Exception as e:
                    print(f"[PROGRESSION] Prediction error (non-fatal): {e}")
        else:
            if technique_id:
                print(f"[PROGRESSION] Technique {technique_id} not in model vocabulary. "
                      f"Stored as evidence only.")

    def _print_prediction(self, preds):
        print("[PREDICTOR] Top-5 next techniques:")
        for rank, (tid, score) in enumerate(preds, 1):
            print(f"  {rank}. {tid}  (score={score:.4f})")