import json
from typing import Any, Dict, List

from .semantic_wazuh_helpers import get_nested_field, evaluate_semantic_conditions


class WazuhMappingEngine:
    """
    JSON-native Wazuh semantic mapping engine.

    Reads a JSON mapping database (with nested AND/OR semantic_conditions)
    and evaluates each Wazuh event against it.
    """

    def __init__(self, mapping_path: str):
        self.mapping_path = mapping_path
        self.mappings: List[Dict[str, Any]] = []
        self.load_database()
        print(
            f"[WAZUH MAPPER] Loaded "
            f"{len(self.mappings)} JSON mappings from {mapping_path}"
        )

    # =========================================================
    # DATABASE
    # =========================================================

    def load_database(self):
        try:
            with open(self.mapping_path, "r", encoding="utf-8") as f:
                db = json.load(f)
        except FileNotFoundError:
            print(
                f"[WAZUH MAPPER] ERROR: "
                f"Mapping database not found: {self.mapping_path}"
            )
            raise
        except json.JSONDecodeError as e:
            print(
                f"[WAZUH MAPPER] ERROR: "
                f"Invalid JSON in mapping database: {e}"
            )
            raise

        if isinstance(db, dict):
            self.mappings = db.get("mappings", [])
        elif isinstance(db, list):
            self.mappings = db
        else:
            raise ValueError(
                "Mapping database must be a JSON object or array"
            )

    # =========================================================
    # MAP MANY EVENTS
    # =========================================================

    def map_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        mapped_summary = []

        for event in events:
            decoded_fields = event.get("decoded_fields", {})
            event_matches = []

            # -------------------------------------------------
            # Evaluate every mapping
            # -------------------------------------------------

            for mapping in self.mappings:
                required = mapping.get("required_fields", [])

                if not self._has_required_fields(decoded_fields, required):
                    continue

                conditions = mapping.get("semantic_conditions")
                if not conditions:
                    continue

                if evaluate_semantic_conditions(decoded_fields, conditions):
                    confidence = float(
                        mapping.get("confidence_score", 0.5)
                    )

                    event_matches.append({
                        "mapping_id": mapping["mapping_id"],
                        "technique": mapping["attack_technique"],
                        "confidence_score": confidence,
                        "match": {
                            "matched": True,
                            "score": 1.0,
                            "matched_fields": required
                        }
                    })

            # -------------------------------------------------
            # No match? Skip silently.
            # -------------------------------------------------

            if not event_matches:
                continue

            results.append({
                "event": event,
                "mappings": event_matches
            })

            # -------------------------------------------------
            # Print successful mapping (same format as Zeek)
            # -------------------------------------------------

            event_id = (
                decoded_fields.get("rule", {}).get("id")
                or decoded_fields.get("id")
                or decoded_fields.get("event_id")
                or "N/A"
            )

            provider = (
                decoded_fields.get("decoder", {}).get("name")
                or decoded_fields.get("provider")
                or "N/A"
            )

            print()
            print("=" * 80)
            print("[WAZUH → MITRE ATT&CK] SEMANTIC MATCH")
            print("=" * 80)
            print(f"Event ID : {event_id}")
            print(f"Provider : {provider}")

            for match in event_matches:
                technique = match["technique"]

                print(
                    f"Technique : "
                    f"{technique['technique_id']} - {technique['technique_name']}"
                )
                print(f"Tactic    : {technique['tactic']}")
                print(f"Score     : {match['match']['score']:.4f}")
                print(f"Confidence: {match['confidence_score']:.4f}")
                print(
                    f"Matched   : "
                    f"{', '.join(match['match']['matched_fields'])}"
                )

                mapped_summary.append({
                    "event_id": event_id,
                    "technique_id": technique["technique_id"],
                    "technique_name": technique["technique_name"],
                    "tactic": technique["tactic"],
                    "score": match["match"]["score"],
                    "confidence": match["confidence_score"],
                    "matched_fields": match["match"]["matched_fields"]
                })

            print("=" * 80)

        # =========================================================
        # FINAL SUMMARY
        # =========================================================

        if mapped_summary:
            print()
            print("#" * 80)
            print("[WAZUH → MITRE ATT&CK] MAPPING SUMMARY")
            print("#" * 80)
            print(f"Total mapped events     : {len(results)}")
            print(f"Total technique mappings: {len(mapped_summary)}")
            print()

            for index, item in enumerate(mapped_summary, start=1):
                print(
                    f"{index}. Event {item['event_id']} → "
                    f"{item['technique_id']} {item['technique_name']} | "
                    f"Tactic={item['tactic']} | "
                    f"Score={item['score']:.4f} | "
                    f"Confidence={item['confidence']:.4f} | "
                    f"Matched={', '.join(item['matched_fields'])}"
                )

            print("#" * 80)

        return results

    # =========================================================
    # REQUIRED FIELDS GUARD
    # =========================================================

    def _has_required_fields(
        self,
        decoded_fields: dict,
        required: List[str]
    ) -> bool:
        """
        Skip mapping if any required dot-notation path is missing or None.
        """
        for path in required:
            if get_nested_field(decoded_fields, path) is None:
                return False
        return True