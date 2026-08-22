from datetime import datetime, timezone

from storage.progression_store import ProgressionStore
from prediction.predictor import AttackPredictor
from pipeline.progression_filter import ProgressionFilter


DEFAULT_USER_ID = "lab_attacker"


class ProgressionIntegration:
    """
    Glue layer between semantic mappings and the prediction model.
    Includes progression filtering before timeline update.
    """

    def __init__(self,
                 predictor=None,
                 progression_store=None,
                 progression_filter=None,
                 default_user=DEFAULT_USER_ID):
        self.default_user = default_user
        self.store = progression_store or ProgressionStore()
        self.predictor = predictor or AttackPredictor()
        self.filter = progression_filter or ProgressionFilter()

    # -----------------------------------------------------------------
    # IP Extraction
    # -----------------------------------------------------------------
    def _extract_ips(self, event, source):
        """
        Robust IP extraction from normalized Zeek/Wazuh events.
        """
        decoded = event.get("decoded_fields", {})
        source_ip = None
        dest_ip = None

        if source == "Zeek":
            for key in ["id.orig_h", "ssh.id.orig_h", "conn.id.orig_h",
                        "http.id.orig_h", "dns.id.orig_h"]:
                val = decoded.get(key)
                if val:
                    source_ip = val
                    break
            for key in ["id.resp_h", "ssh.id.resp_h", "conn.id.resp_h",
                        "http.id.resp_h", "dns.id.resp_h"]:
                val = decoded.get(key)
                if val:
                    dest_ip = val
                    break
            # files.log uses tx_hosts / rx_hosts (can be list)
            if not source_ip:
                tx = decoded.get("files.tx_hosts")
                if isinstance(tx, list) and tx:
                    source_ip = tx[0]
                elif isinstance(tx, str):
                    source_ip = tx
            if not dest_ip:
                rx = decoded.get("files.rx_hosts")
                if isinstance(rx, list) and rx:
                    dest_ip = rx[0]
                elif isinstance(rx, str):
                    dest_ip = rx

        elif source == "Wazuh":
            data = decoded.get("data", {})
            source_ip = data.get("srcip")
            dest_ip = data.get("dstip")
            if not source_ip:
                source_ip = decoded.get("srcip") or decoded.get("source_ip")
            if not dest_ip:
                dest_ip = decoded.get("dstip") or decoded.get("destination_ip")

        return source_ip, dest_ip

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
        accepted_count = 0

        for item in results:
            event = item.get("event", {})
            matches = item.get("matches", [])

            for match in matches:
                match_count += 1
                accepted = self._handle_match(
                    source="Zeek",
                    log_type=log_type,
                    event=event,
                    match=match
                )
                if accepted:
                    accepted_count += 1

        print(f"[PROGRESSION] Zeek: {match_count} semantic matches, {accepted_count} accepted")
        return match_count

    # -----------------------------------------------------------------
    # Wazuh
    # -----------------------------------------------------------------
    def process_wazuh_mapped_events(self, mapped_events):
        """
        mapped_events: list from map_wazuh_events()
        """
        match_count = 0
        accepted_count = 0

        for item in mapped_events:
            if item.get("correlation") is True:
                continue

            event = item.get("event", {})
            mappings = item.get("mappings", [])

            for match in mappings:
                match_count += 1
                accepted = self._handle_match(
                    source="Wazuh",
                    log_type=event.get("log_type", "unknown"),
                    event=event,
                    match=match
                )
                if accepted:
                    accepted_count += 1

        print(f"[PROGRESSION] Wazuh: {match_count} semantic matches, {accepted_count} accepted")
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
            technique_id = match.get("technique_id")
            technique_name = match.get("technique_name")
            tactic = match.get("tactic")
            mapping_id = match.get("mapping_id")
            confidence = match.get("confidence_score", 0.0)
            score = match.get("score", 0.0)

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

        # Timestamp
        timestamp = event.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        # IPs
        source_ip, dest_ip = self._extract_ips(event, source)

        # Event ID
        raw_event_id = event.get("id") or event.get("event_id") or "unknown"

        # Build attack event record
        attack_event = {
            "event_id": raw_event_id,
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
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "raw_event": event,
            "progression_eligible": False,
            "progression_reason": None,
            "progression_rejected_reason": None
        }

        # Print semantic mapping
        print()
        print("[SEMANTIC]")
        print(f"  Technique : {technique_id} {technique_name or ''}")
        print(f"  Source    : {source}/{log_type}")
        print(f"  Confidence: {confidence}")
        print(f"  Score     : {score}")
        if source_ip:
            print(f"  Source IP : {source_ip}")

        # Get current sequence for filtering
        current_seq = self.store.get_sequence(self.default_user)

        # Evaluate filter
        eligible, reason = self.filter.evaluate(attack_event, current_seq)

        # Check deduplication
        is_dup = self.store.is_duplicate(
            self.default_user,
            attack_event["event_id"],
            technique_id,
            mapping_id
        )

        if eligible and not is_dup:
            attack_event["progression_eligible"] = True
            attack_event["progression_reason"] = reason
            self.store.store_attack_event(attack_event)

            print("[PROGRESSION]")
            print("  ACCEPTED")
            print(f"  Reason    : {reason}")
            print(f"  User      : {self.default_user}")

            # Vocabulary filter
            vocab = set(self.predictor.vocab) if self.predictor.vocab else set()
            if technique_id and technique_id in vocab:
                full_sequence = self.store.append_technique(
                    self.default_user,
                    technique_id,
                    timestamp
                )

                print("[TIMELINE]")
                print(f"  Appended  : {technique_id}")
                print(f"  Sequence  : {' -> '.join(full_sequence)}")

                if len(full_sequence) >= 1:
                    try:
                        preds = self.predictor.predict(full_sequence, top_k=5)
                        if preds:
                            pred_record = self.store.store_prediction(
                                self.default_user,
                                full_sequence,
                                preds
                            )
                            print("[PREDICTION]")
                            print(f"  Prediction ID: {pred_record['prediction_id']}")
                            print(f"  Current chain:")
                            print(f"    {' -> '.join(full_sequence)}")
                            print("  Top-5 next techniques:")
                            for rank, (tid, pscore) in enumerate(preds, 1):
                                print(f"    {rank}. {tid}  (score={pscore:.4f})")
                    except Exception as e:
                        print(f"[PREDICTION] ERROR: {e}")
            else:
                if technique_id:
                    print(f"[PROGRESSION] Technique {technique_id} not in model vocabulary. Stored as evidence only.")
            return True

        else:
            attack_event["progression_eligible"] = False
            if is_dup:
                attack_event["progression_rejected_reason"] = "duplicate_event"
            else:
                attack_event["progression_rejected_reason"] = reason

            self.store.store_attack_event(attack_event)

            print("[PROGRESSION]")
            print("  REJECTED")
            print(f"  Reason    : {attack_event['progression_rejected_reason']}")
            return False