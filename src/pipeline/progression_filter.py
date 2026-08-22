import json
from pathlib import Path

try:
    from prediction.predictor import TID_TO_TACTIC
except ImportError:
    TID_TO_TACTIC = {}


class ProgressionFilter:
    """
    Decides whether a semantically-mapped event should enter the attack progression timeline.
    """

    def __init__(self, config_path="config/progression_config.json"):
        self.config = self._load_config(config_path)
        self.attacker_ips = set(
            self.config.get("attacker", {}).get("source_ips", [])
        )
        self.ignore_ips = set(
            self.config.get("ignore_source_ips", [])
        )
        self.user_id = self.config.get("attacker", {}).get("user_id", "lab_attacker")
        self.rules = self.config.get("filter_rules", {})
        self.global_rules = self.rules.get("global", {})
        self.by_technique = self.rules.get("by_technique", {})
        self.by_tactic = self.rules.get("by_tactic", {})
        self.dedup_window = self.rules.get("deduplication", {}).get("window_seconds", 300)


    def _load_config(self, path):
        p = Path(path)
        if not p.exists():
            print(f"[FILTER] WARNING: Config not found at {path}, using empty rules.")
            return {}
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    def evaluate(self, attack_event, current_sequence):
        """
        Returns: (eligible: bool, reason: str)
        """
        technique_id = attack_event.get("technique_id")
        source_ip = attack_event.get("source_ip")
        confidence = attack_event.get("confidence", 0.0)
        score = attack_event.get("score", 0.0)
        tactic = attack_event.get("tactic", "")

        # 0. Always ignore collector/infrastructure IPs
        if source_ip and source_ip in self.ignore_ips:
            return False, f"ignored_source_ip:{source_ip}"

        # 1. Global thresholds
        min_conf = self.global_rules.get("min_confidence", 0.0)
        min_score = self.global_rules.get("min_score", 0.0)
        if confidence < min_conf:
            return False, f"confidence_below_threshold:{confidence:.3f}<{min_conf}"
        if score < min_score:
            return False, f"score_below_threshold:{score:.3f}<{min_score}"

        # 2. Technique-specific rules
        tech_rule = self.by_technique.get(technique_id, {})
        if tech_rule.get("require_attacker_source_ip", False):
            if not source_ip:
                return False, "source_ip_missing"
            if source_ip not in self.attacker_ips:
                return False, "source_ip_not_attacker"

        # 3. Tactic-level sequence deduplication
        if tactic and tactic in self.by_tactic:
            tactic_rule = self.by_tactic[tactic]
            max_occ = tactic_rule.get("max_occurrences_in_sequence", -1)
            if max_occ > 0:
                tactic_count = sum(
                    1 for tid in current_sequence
                    if TID_TO_TACTIC.get(tid) == tactic
                )
                if tactic_count >= max_occ:
                    reason = tactic_rule.get(
                        "reason_on_reject",
                        f"{tactic}_max_occurrences_reached"
                    )
                    return False, reason

        # 4. Exact technique dedup in sequence (unless repeats explicitly allowed)
        if technique_id in current_sequence:
            if not tech_rule.get("allow_repeats", False):
                return False, "technique_already_in_sequence"

        return True, "attacker_source_ip" if (source_ip in self.attacker_ips) else "passed_all_rules"



    