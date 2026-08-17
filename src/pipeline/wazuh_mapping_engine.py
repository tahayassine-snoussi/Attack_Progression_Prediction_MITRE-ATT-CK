import json

from typing import (
    Any,
    Dict,
    List
)

from .semantic_wazuh_helpers import (
    get_nested_field,
    evaluate_semantic_conditions
)

from .wazuh_correlation_engine import (
    WazuhCorrelationEngine
)


class WazuhMappingEngine:
    """
    JSON-native Wazuh mapping engine.

    Responsibilities:

        1. Load Wazuh mapping database.
        2. Evaluate direct semantic mappings per event.
        3. Skip correlation mappings during event-level mapping.
        4. Run correlation engine once against the complete event set.
        5. Merge semantic and correlation results.
    """

    def __init__(
        self,
        mapping_path: str
    ):

        self.mapping_path = mapping_path

        self.mappings: List[
            Dict[str, Any]
        ] = []

        # =====================================================
        # LOAD DATABASE
        # =====================================================

        self.load_database()

        # =====================================================
        # CORRELATION ENGINE
        # =====================================================

        self.correlation_engine = (
            WazuhCorrelationEngine(
                self.mappings
            )
        )

        print(
            f"[WAZUH MAPPER] Loaded "
            f"{len(self.mappings)} JSON mappings "
            f"from {mapping_path}"
        )

    # =========================================================
    # DATABASE
    # =========================================================

    def load_database(self):

        try:

            with open(
                self.mapping_path,
                "r",
                encoding="utf-8"
            ) as f:

                db = json.load(f)

        except FileNotFoundError:

            print(
                f"[WAZUH MAPPER] ERROR: "
                f"Mapping database not found: "
                f"{self.mapping_path}"
            )

            raise

        except json.JSONDecodeError as error:

            print(
                f"[WAZUH MAPPER] ERROR: "
                f"Invalid JSON in mapping database: "
                f"{error}"
            )

            raise

        if isinstance(db, dict):

            self.mappings = db.get(
                "mappings",
                []
            )

        elif isinstance(db, list):

            self.mappings = db

        else:

            raise ValueError(
                "Mapping database must be "
                "a JSON object or array"
            )

    # =========================================================
    # MAP MANY EVENTS
    # =========================================================

    def map_events(
        self,
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:

        results: List[
            Dict[str, Any]
        ] = []

        mapped_summary: List[
            Dict[str, Any]
        ] = []

        if not events:

            print(
                "[WAZUH MAPPER] "
                "No events received."
            )

            return results

        # =====================================================
        # STEP 1
        # DIRECT SEMANTIC MAPPING
        # =====================================================

        for event in events:

            decoded_fields = event.get(
                "decoded_fields",
                {}
            )

            event_matches: List[
                Dict[str, Any]
            ] = []

            # -------------------------------------------------
            # Check every mapping
            # -------------------------------------------------

            for mapping in self.mappings:

                # =================================================
                # CORRELATION MAPPINGS
                # =================================================

                if mapping.get(
                    "correlation_required",
                    False
                ):

                    continue

                # =================================================
                # REQUIRED FIELDS
                # =================================================

                required = mapping.get(
                    "required_fields",
                    []
                )

                if not self._has_required_fields(
                    decoded_fields,
                    required
                ):

                    continue

                # =================================================
                # SEMANTIC CONDITIONS
                # =================================================

                conditions = mapping.get(
                    "semantic_conditions"
                )

                if not conditions:

                    continue

                # =================================================
                # EVALUATE CONDITIONS
                # =================================================

                if not evaluate_semantic_conditions(
                    decoded_fields,
                    conditions
                ):

                    continue

                # =================================================
                # BUILD SEMANTIC MATCH
                # =================================================

                confidence = float(
                    mapping.get(
                        "confidence_score",
                        0.5
                    )
                )

                event_matches.append({

                    "mapping_id":
                        mapping.get(
                            "mapping_id",
                            "UNKNOWN"
                        ),

                    "technique":
                        mapping.get(
                            "attack_technique",
                            {}
                        ),

                    "confidence_score":
                        confidence,

                    "mapping_type":
                        mapping.get(
                            "mapping_type",
                            "semantic"
                        ),

                    "match": {

                        "matched":
                            True,

                        "score":
                            1.0,

                        "matched_fields":
                            required
                    }
                })

            # =====================================================
            # NO SEMANTIC MATCH
            # =====================================================

            if not event_matches:
                continue

            # =====================================================
            # STORE EVENT RESULT
            # =====================================================

            results.append({

                "event":
                    event,

                "mappings":
                    event_matches

            })

            # =====================================================
            # EVENT ID
            # =====================================================

            event_id = (

                decoded_fields
                .get(
                    "rule",
                    {}
                )
                .get("id")

                or decoded_fields.get(
                    "id"
                )

                or decoded_fields.get(
                    "event_id"
                )

                or "N/A"
            )

            # =====================================================
            # PROVIDER
            # =====================================================

            provider = (

                decoded_fields
                .get(
                    "decoder",
                    {}
                )
                .get("name")

                or decoded_fields.get(
                    "provider"
                )

                or "N/A"
            )

            # =====================================================
            # PRINT SEMANTIC MATCH
            # =====================================================

            print()

            print(
                "=" * 80
            )

            print(
                "[WAZUH → MITRE ATT&CK] "
                "SEMANTIC MATCH"
            )

            print(
                "=" * 80
            )

            print(
                f"Event ID : {event_id}"
            )

            print(
                f"Provider : {provider}"
            )

            # -------------------------------------------------
            # Print every technique
            # -------------------------------------------------

            for match in event_matches:

                technique = match[
                    "technique"
                ]

                print(
                    f"Technique : "
                    f"{technique.get('technique_id', 'N/A')} - "
                    f"{technique.get('technique_name', 'N/A')}"
                )

                print(
                    f"Tactic    : "
                    f"{technique.get('tactic', 'N/A')}"
                )

                print(
                    f"Score     : "
                    f"{match['match']['score']:.4f}"
                )

                print(
                    f"Confidence: "
                    f"{match['confidence_score']:.4f}"
                )

                print(
                    f"Type      : "
                    f"{match['mapping_type']}"
                )

                matched_fields = (
                    match["match"]
                    .get(
                        "matched_fields",
                        []
                    )
                )

                print(
                    f"Matched   : "
                    f"{', '.join(matched_fields)}"
                )

                # -------------------------------------------------
                # Summary record
                # -------------------------------------------------

                mapped_summary.append({

                    "event_id":
                        event_id,

                    "technique_id":
                        technique.get(
                            "technique_id",
                            "N/A"
                        ),

                    "technique_name":
                        technique.get(
                            "technique_name",
                            "N/A"
                        ),

                    "tactic":
                        technique.get(
                            "tactic",
                            "N/A"
                        ),

                    "score":
                        match["match"][
                            "score"
                        ],

                    "confidence":
                        match[
                            "confidence_score"
                        ],

                    "mapping_type":
                        match[
                            "mapping_type"
                        ],

                    "matched_fields":
                        matched_fields

                })

            print(
                "=" * 80
            )

        # =====================================================
        # STEP 2
        # CORRELATION ENGINE
        #
        # IMPORTANT:
        #
        # Run exactly ONCE against ALL events.
        #
        # Example:
        #
        #     SSH event
        #          +
        #     whoami event
        #          =
        #     T1059.004
        # =====================================================

        correlation_results = (
            self.correlation_engine.detect(
                events
            )
        )

        # =====================================================
        # MERGE CORRELATION RESULTS
        # =====================================================

        if correlation_results:

            print()

            print(
                f"[WAZUH MAPPER] "
                f"Correlation detections: "
                f"{len(correlation_results)}"
            )

            for correlation_result in (
                correlation_results
            ):

                results.append({

                    "correlation":
                        True,

                    **correlation_result

                })

        # =====================================================
        # STEP 3
        # FINAL SUMMARY
        # =====================================================

        if mapped_summary:

            print()

            print(
                "#" * 80
            )

            print(
                "[WAZUH → MITRE ATT&CK] "
                "MAPPING SUMMARY"
            )

            print(
                "#" * 80
            )

            print(
                f"Total mapped events     : "
                f"{len(results)}"
            )

            print(
                f"Total technique mappings: "
                f"{len(mapped_summary)}"
            )

            print()

            for index, item in enumerate(
                mapped_summary,
                start=1
            ):

                print(
                    f"{index}. "
                    f"Event {item['event_id']} → "
                    f"{item['technique_id']} "
                    f"{item['technique_name']} | "
                    f"Tactic={item['tactic']} | "
                    f"Type={item['mapping_type']} | "
                    f"Score={item['score']:.4f} | "
                    f"Confidence={item['confidence']:.4f} | "
                    f"Matched="
                    f"{', '.join(item['matched_fields'])}"
                )

            print(
                "#" * 80
            )

        # =====================================================
        # RETURN
        # =====================================================

        return results

    # =========================================================
    # REQUIRED FIELDS GUARD
    # =========================================================

    def _has_required_fields(
        self,
        decoded_fields: Dict[str, Any],
        required: List[str]
    ) -> bool:

        """
        Skip mapping if any required dot-notation path
        is missing or None.
        """

        for path in required:

            if get_nested_field(
                decoded_fields,
                path
            ) is None:

                return False

        return True