import json
import time
from pathlib import Path

try:
    from prediction.predictor import TID_TO_TACTIC
except ImportError:
    TID_TO_TACTIC = {}


class ProgressionFilter:
    """
    Decides whether a semantically-mapped or correlated event should enter the attack progression timeline.
    """

    def __init__(self, config_path="src/config/progression_config.json"):
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

        self.default_require_attacker_ip = self.config.get(
            "default_require_attacker_source_ip", False
        )

        cooldown_cfg = self.config.get("source_ip_cooldown", {})
        self.cooldown_enabled = cooldown_cfg.get("enabled", False)
        self.cooldown_seconds = cooldown_cfg.get("window_seconds", 30)
        self.cooldown_exempt = set(cooldown_cfg.get("exempt_techniques", []))

        # In-memory cache: source_ip -> last_accepted_timestamp
        self._cooldown_cache = {}

        print(f"[FILTER] Config loaded: {config_path}")
        print(f"[FILTER] Attacker IPs : {self.attacker_ips}")
        print(f"[FILTER] Ignore IPs   : {self.ignore_ips}")
        print(f"[FILTER] Default req attacker IP: {self.default_require_attacker_ip}")
        print(f"[FILTER] Cooldown     : {self.cooldown_enabled} ({self.cooldown_seconds}s)")

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

        print(f"[FILTER] Evaluating {technique_id} from src={source_ip} "
              f"conf={confidence} score={score}")

        # 0. Always ignore collector/infrastructure IPs
        if source_ip and source_ip in self.ignore_ips:
            print(f"[FILTER] -> REJECTED (ignored_source_ip: {source_ip})")
            return False, f"ignored_source_ip:{source_ip}"

        # 0.5 Reject known infrastructure noise
        agent_name = attack_event.get("agent_name")
        if agent_name == "wazuh-server" and technique_id == "T1548.003":
            print(f"[FILTER] -> REJECTED (infrastructure_agent: {agent_name})")
            return False, "infrastructure_agent"

        # 1.5 Session correlation: local escalation after attacker remote access
        if technique_id == "T1548.003" and not source_ip:
            if any(tid in current_sequence for tid in ("T1021.004", "T1078")):
                print(f"[FILTER] -> ACCEPTED (post_ssh_escalation)")
                return True, "post_ssh_escalation"

        # 1. Global thresholds
        min_conf = self.global_rules.get("min_confidence", 0.0)
        min_score = self.global_rules.get("min_score", 0.0)
        if confidence < min_conf:
            return False, f"confidence_below_threshold:{confidence:.3f}<{min_conf}"
        if score < min_score:
            return False, f"score_below_threshold:{score:.3f}<{min_score}"

        # 2. Technique-specific or default source-IP requirement
        tech_rule = self.by_technique.get(technique_id, {})
        requires_attacker_ip = tech_rule.get(
            "require_attacker_source_ip",
            self.default_require_attacker_ip
        )

        if requires_attacker_ip:
            if not source_ip:
                print(f"[FILTER] -> REJECTED (source_ip_missing)")
                return False, "source_ip_missing"
            if source_ip not in self.attacker_ips:
                print(f"[FILTER] -> REJECTED (source_ip_not_attacker: {source_ip})")
                return False, "source_ip_not_attacker"

        # 3. Source-IP cooldown (prevents nmap scan floods)
        if self.cooldown_enabled and source_ip:
            if technique_id not in self.cooldown_exempt:
                now = time.time()
                last = self._cooldown_cache.get(source_ip)
                if last is not None and (now - last) < self.cooldown_seconds:
                    remaining = int(self.cooldown_seconds - (now - last))
                    print(f"[FILTER] -> REJECTED (source_ip_cooldown: {source_ip}, {remaining}s remaining)")
                    return False, f"source_ip_cooldown:{source_ip}"

        # 4. Tactic-level sequence deduplication
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
                    print(f"[FILTER] -> REJECTED ({reason})")
                    return False, reason

        # 5. Exact technique dedup in sequence (unless repeats explicitly allowed)
        if technique_id in current_sequence:
            if not tech_rule.get("allow_repeats", False):
                print(f"[FILTER] -> REJECTED (technique_already_in_sequence)")
                return False, "technique_already_in_sequence"

        # Record acceptance time for cooldown
        if source_ip:
            self._cooldown_cache[source_ip] = time.time()

        reason = "attacker_source_ip" if (source_ip in self.attacker_ips) else "passed_all_rules"
        print(f"[FILTER] -> ACCEPTED ({reason})")
        return True, reason