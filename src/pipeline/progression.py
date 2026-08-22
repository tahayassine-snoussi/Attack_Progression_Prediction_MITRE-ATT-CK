import ast
from datetime import datetime, timezone

from storage.progression_store import ProgressionStore
from prediction.predictor import AttackPredictor
from pipeline.progression_filter import ProgressionFilter


DEFAULT_USER_ID = "lab_attacker"


class ProgressionIntegration:
    """
    Glue layer between semantic mappings / correlation detections and the prediction model.
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

    def _extract_ips_from_correlation(self, detection):
        """
        Correlation detections aggregate multiple events.
        Try group_key first, then fallback to first event.
        """
        group_key = detection.get("group_key")
        if group_key:
            try:
                gk = ast.literal_eval(group_key)
                if isinstance(gk, (list, tuple)) and len(gk) >= 1:
                    src = gk[0]
                    dst = gk[1] if len(gk) > 1 else None
                    if src and isinstance(src, str):
                        src = src.split(':')[0]
                    if dst and isinstance(dst, str):
                        dst = dst.split(':')[0]
                    return src, dst
            except Exception:
                pass

        events = detection.get("events", [])
        if events:
            return self._extract_ips(events[0], "Zeek")
        return None, None

    # -----------------------------------------------------------------
    # Zeek Semantic
    # -----------------------------------------------------------------
    def process_zeek_semantic_results(self, semantic_results, log_type):
        results = semantic_results.get("semantic_results", [])
        match_count = 0
        accepted_count = 0

        for item in results:
            event = item.get("event", {})
            matches = item.get("matches", [])

            for match in matches:
                match_count += 1
                if self._handle_mapping("Zeek", log_type, event, match):
                    accepted_count += 1

        print(f"[PROGRESSION] Zeek semantic: {match_count} matches, {accepted_count} accepted")
        return match_count

    # -----------------------------------------------------------------
    # Zeek Correlation
    # -----------------------------------------------------------------
    def process_zeek_correlation_results(self, correlation_results, log_type):
        accepted_count = 0

        for detection in correlation_results:
            technique = detection.get("attack_technique", {})
            technique_id = technique.get("technique_id")
            technique_name = technique.get("technique_name")
            tactic = technique.get("tactic")
            mapping_id = detection.get("mapping_id", "UNKNOWN")
            confidence = float(detection.get("confidence_score", 0.0))
            time_group_id = detection.get("time_group_id", "unknown")
            group_key = detection.get("group_key", "unknown")

            source_ip, dest_ip = self._extract_ips_from_correlation(detection)

            # Stable dedup key for correlation aggregates
            raw_event_id = f"corr:{mapping_id}:{time_group_id}:{group_key}"

            attack_event = {
                "event_id": raw_event_id,
                "user_id": self.default_user,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "Zeek",
                "log_type": log_type,
                "mapping_id": mapping_id,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": tactic,
                "confidence": confidence,
                "score": confidence,
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "raw_event": detection,
                "progression_eligible": False,
                "progression_reason": None,
                "progression_rejected_reason": None
            }

            print()
            print("[SEMANTIC-CORR]")
            print(f"  Technique : {technique_id} {technique_name or ''}")
            print(f"  Source    : Zeek/{log_type}")
            print(f"  Confidence: {confidence}")
            print(f"  Source IP : {source_ip}")

            if self._evaluate_and_store(attack_event):
                accepted_count += 1

        print(f"[PROGRESSION] Zeek correlation: {len(correlation_results)} detections, {accepted_count} accepted")
        return accepted_count

    # -----------------------------------------------------------------
    # Wazuh
    # -----------------------------------------------------------------
    def process_wazuh_mapped_events(self, mapped_events):
        match_count = 0
        accepted_count = 0

        for item in mapped_events:
            if item.get("correlation") is True:
                continue

            event = item.get("event", {})
            mappings = item.get("mappings", [])

            for match in mappings:
                match_count += 1
                if self._handle_mapping("Wazuh", event.get("log_type", "unknown"), event, match):
                    accepted_count += 1

        print(f"[PROGRESSION] Wazuh: {match_count} semantic matches, {accepted_count} accepted")
        return match_count

    # -----------------------------------------------------------------
    # Common mapping handler
    # -----------------------------------------------------------------
    def _handle_mapping(self, source, log_type, event, match):
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

        timestamp = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        source_ip, dest_ip = self._extract_ips(event, source)
        raw_event_id = event.get("id") or event.get("event_id") or "unknown"

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

        print()
        print("[SEMANTIC]")
        print(f"  Technique : {technique_id} {technique_name or ''}")
        print(f"  Source    : {source}/{log_type}")
        print(f"  Confidence: {confidence}")
        print(f"  Score     : {score}")
        print(f"  Source IP : {source_ip}")

        return self._evaluate_and_store(attack_event)

    # -----------------------------------------------------------------
    # Evaluate + store + predict
    # -----------------------------------------------------------------
    def _evaluate_and_store(self, attack_event):
        technique_id = attack_event.get("technique_id")
        current_seq = self.store.get_sequence(self.default_user)

        # Duplicate check
        is_dup = self.store.is_duplicate(
            self.default_user,
            attack_event["event_id"],
            technique_id,
            attack_event.get("mapping_id")
        )

        if is_dup:
            attack_event["progression_eligible"] = False
            attack_event["progression_rejected_reason"] = "duplicate_event"
            self.store.store_attack_event(attack_event)
            print("[PROGRESSION]")
            print("  REJECTED")
            print("  Reason    : duplicate_event")
            return False

        eligible, reason = self.filter.evaluate(attack_event, current_seq)

        if eligible:
            attack_event["progression_eligible"] = True
            attack_event["progression_reason"] = reason
            self.store.store_attack_event(attack_event)

            print("[PROGRESSION]")
            print("  ACCEPTED")
            print(f"  Reason    : {reason}")
            print(f"  User      : {self.default_user}")

            vocab = set(self.predictor.vocab) if self.predictor.vocab else set()
            if technique_id and technique_id in vocab:
                full_sequence = self.store.append_technique(
                    self.default_user,
                    technique_id,
                    attack_event["timestamp"]
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
            attack_event["progression_rejected_reason"] = reason
            self.store.store_attack_event(attack_event)

            print("[PROGRESSION]")
            print("  REJECTED")
            print(f"  Reason    : {reason}")
            return False