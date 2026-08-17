from typing import Any, Dict, List

from .semantic_wazuh_helpers import (
    get_nested_field,
    evaluate_semantic_conditions
)


class WazuhCorrelationEngine:
    """
    Wazuh semantic correlation engine.

    Correlation model:

        SOURCE EVENT
            |
            | establishes attacker/session context
            v
        FOLLOW-UP EVENT
            |
            | satisfies behavior
            v
        CORRELATED MITRE TECHNIQUE

    Example:

        SSH from 192.168.56.40
                +
        whoami executed in resulting session
                =
        T1059.004 - Unix Shell
    """

    def __init__(
        self,
        mappings: List[Dict[str, Any]]
    ):
        self.mappings = mappings

        print(
            "[WAZUH CORRELATION] Engine initialized"
        )

    # =========================================================
    # PUBLIC API
    # =========================================================

    def detect(
        self,
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:

        results: List[Dict[str, Any]] = []

        if not events:
            return results

        for mapping in self.mappings:

            correlation = mapping.get(
                "semantic_correlation"
            )

            # -------------------------------------------------
            # Ignore mappings that do not contain correlation
            # -------------------------------------------------

            if not correlation:
                continue

            mapping_id = mapping.get(
                "mapping_id",
                "UNKNOWN"
            )

            print(
                f"[WAZUH CORRELATION] "
                f"Checking {mapping_id}"
            )

            # =================================================
            # FIND SOURCE EVENTS
            # =================================================

            source_events = (
                self._find_source_events(
                    events,
                    correlation.get(
                        "source_event",
                        {}
                    )
                )
            )

            if not source_events:

                print(
                    f"[WAZUH CORRELATION] "
                    f"Rejected {mapping_id} "
                    f"(no source event)"
                )

                continue

            # =================================================
            # FIND FOLLOW-UP EVENTS
            # =================================================

            followup_events = (
                self._find_followup_events(
                    events,
                    correlation.get(
                        "followup_event",
                        {}
                    )
                )
            )

            if not followup_events:

                print(
                    f"[WAZUH CORRELATION] "
                    f"Rejected {mapping_id} "
                    f"(no follow-up event)"
                )

                continue

            # =================================================
            # SOURCE + FOLLOW-UP CORRELATION
            # =================================================

            mapping_matches = 0

            for source in source_events:

                for followup in followup_events:

                    # -----------------------------------------
                    # Never correlate an event with itself
                    # -----------------------------------------

                    if source is followup:
                        continue

                    # -----------------------------------------
                    # Context validation
                    # -----------------------------------------

                    if not self._same_context(
                        source,
                        followup,
                        correlation
                    ):
                        continue

                    # -----------------------------------------
                    # Time-window validation
                    # -----------------------------------------

                    if not self._within_time_window(
                        source,
                        followup,
                        correlation
                    ):
                        continue

                    # -----------------------------------------
                    # Build evidence
                    # -----------------------------------------

                    evidence = (
                        self._build_evidence(
                            source,
                            followup,
                            correlation
                        )
                    )

                    # -----------------------------------------
                    # Build correlation result
                    # -----------------------------------------

                    result = {

                        "mapping_id":
                            mapping_id,

                        "technique":
                            mapping.get(
                                "attack_technique",
                                {}
                            ),

                        "confidence_score":
                            float(
                                mapping.get(
                                    "confidence_score",
                                    0.5
                                )
                            ),

                        "mapping_type":
                            "semantic_correlation",

                        "correlation": {

                            "matched":
                                True,

                            "relationship":
                                correlation.get(
                                    "relationship",
                                    "source_followup"
                                ),

                            "time_window_seconds":
                                correlation.get(
                                    "time_window_seconds"
                                ),

                            "source_event":
                                source,

                            "followup_event":
                                followup,

                            "evidence":
                                evidence
                        }
                    }

                    results.append(
                        result
                    )

                    mapping_matches += 1

                    # -----------------------------------------
                    # Detailed correlation output
                    # -----------------------------------------

                    self._print_match(
                        mapping,
                        source,
                        followup,
                        correlation,
                        evidence
                    )

            # =================================================
            # MAPPING RESULT
            # =================================================

            if mapping_matches == 0:

                print(
                    f"[WAZUH CORRELATION] "
                    f"Rejected {mapping_id} "
                    f"(no matching source/follow-up pair)"
                )

            else:

                print(
                    f"[WAZUH CORRELATION] "
                    f"Mapping {mapping_id}: "
                    f"{mapping_matches} correlated pair(s)"
                )

        return results

    # =========================================================
    # SOURCE EVENT
    # =========================================================

    def _find_source_events(
        self,
        events: List[Dict[str, Any]],
        definition: Dict[str, Any]
    ) -> List[Dict[str, Any]]:

        conditions = definition.get(
            "conditions"
        )

        if not conditions:
            return []

        matches = []

        for event in events:

            decoded = event.get(
                "decoded_fields",
                {}
            )

            if evaluate_semantic_conditions(
                decoded,
                conditions
            ):
                matches.append(event)

        return matches

    # =========================================================
    # FOLLOW-UP EVENT
    # =========================================================

    def _find_followup_events(
        self,
        events: List[Dict[str, Any]],
        definition: Dict[str, Any]
    ) -> List[Dict[str, Any]]:

        conditions = definition.get(
            "conditions"
        )

        if not conditions:
            return []

        matches = []

        for event in events:

            decoded = event.get(
                "decoded_fields",
                {}
            )

            if evaluate_semantic_conditions(
                decoded,
                conditions
            ):
                matches.append(event)

        return matches

    # =========================================================
    # CONTEXT MATCHING
    # =========================================================

    def _same_context(
        self,
        source: Dict[str, Any],
        followup: Dict[str, Any],
        correlation: Dict[str, Any]
    ) -> bool:

        context_fields = correlation.get(
            "context_fields",
            []
        )

        # -----------------------------------------------------
        # No context fields means event existence is enough.
        # -----------------------------------------------------

        if not context_fields:
            return True

        source_decoded = source.get(
            "decoded_fields",
            {}
        )

        followup_decoded = followup.get(
            "decoded_fields",
            {}
        )

        for field in context_fields:

            source_value = get_nested_field(
                source_decoded,
                field
            )

            followup_value = get_nested_field(
                followup_decoded,
                field
            )

            # -------------------------------------------------
            # If one side does not contain the context field,
            # do not reject solely because it is absent.
            # -------------------------------------------------

            if source_value is None:
                continue

            if followup_value is None:
                continue

            if str(source_value) != str(
                followup_value
            ):
                return False

        return True

    # =========================================================
    # TIME WINDOW
    # =========================================================

    def _within_time_window(
        self,
        source: Dict[str, Any],
        followup: Dict[str, Any],
        correlation: Dict[str, Any]
    ) -> bool:

        window = correlation.get(
            "time_window_seconds"
        )

        # -----------------------------------------------------
        # No time window configured.
        # -----------------------------------------------------

        if window is None:
            return True

        try:
            window = float(window)
        except (
            TypeError,
            ValueError
        ):
            return True

        source_timestamp = (
            self._get_timestamp(
                source
            )
        )

        followup_timestamp = (
            self._get_timestamp(
                followup
            )
        )

        # -----------------------------------------------------
        # If timestamps cannot be extracted, do not reject.
        # -----------------------------------------------------

        if source_timestamp is None:
            return True

        if followup_timestamp is None:
            return True

        # -----------------------------------------------------
        # The follow-up should happen after the source.
        # -----------------------------------------------------

        difference = (
            followup_timestamp
            - source_timestamp
        )

        if difference < 0:
            return False

        return difference <= window

    # =========================================================
    # TIMESTAMP EXTRACTION
    # =========================================================

    def _get_timestamp(
        self,
        event: Dict[str, Any]
    ):

        decoded = event.get(
            "decoded_fields",
            {}
        )

        timestamp = (
            decoded.get("timestamp")
            or event.get("timestamp")
        )

        if timestamp is None:
            return None

        # -----------------------------------------------------
        # Numeric timestamps
        # -----------------------------------------------------

        if isinstance(
            timestamp,
            (int, float)
        ):
            return float(timestamp)

        # -----------------------------------------------------
        # ISO timestamp
        # -----------------------------------------------------

        try:
            from datetime import datetime

            value = str(
                timestamp
            )

            if value.endswith("Z"):
                value = value[:-1] + "+00:00"

            return (
                datetime.fromisoformat(
                    value
                ).timestamp()
            )

        except (
            ValueError,
            TypeError,
            OverflowError
        ):
            return None

    # =========================================================
    # EVIDENCE
    # =========================================================

    def _build_evidence(
        self,
        source: Dict[str, Any],
        followup: Dict[str, Any],
        correlation: Dict[str, Any]
    ) -> List[str]:

        evidence = []

        # -----------------------------------------------------
        # Context fields
        # -----------------------------------------------------

        context_fields = correlation.get(
            "context_fields",
            []
        )

        source_decoded = source.get(
            "decoded_fields",
            {}
        )

        followup_decoded = followup.get(
            "decoded_fields",
            {}
        )

        for field in context_fields:

            source_value = get_nested_field(
                source_decoded,
                field
            )

            followup_value = get_nested_field(
                followup_decoded,
                field
            )

            if (
                source_value is not None
                and followup_value is not None
                and str(source_value)
                == str(followup_value)
            ):

                evidence.append(
                    f"context matched: "
                    f"{field}={source_value}"
                )

        # -----------------------------------------------------
        # Time evidence
        # -----------------------------------------------------

        source_timestamp = (
            self._get_timestamp(
                source
            )
        )

        followup_timestamp = (
            self._get_timestamp(
                followup
            )
        )

        if (
            source_timestamp is not None
            and followup_timestamp is not None
        ):

            difference = (
                followup_timestamp
                - source_timestamp
            )

            evidence.append(
                f"time sequence matched: "
                f"follow-up occurred "
                f"{difference:.3f}s after source"
            )

        # -----------------------------------------------------
        # Configured relationship
        # -----------------------------------------------------

        relationship = correlation.get(
            "relationship"
        )

        if relationship:

            evidence.append(
                f"relationship matched: "
                f"{relationship}"
            )

        return evidence

    # =========================================================
    # PRINT CORRELATION MATCH
    # =========================================================

    def _print_match(
        self,
        mapping: Dict[str, Any],
        source: Dict[str, Any],
        followup: Dict[str, Any],
        correlation: Dict[str, Any],
        evidence: List[str]
    ):

        technique = mapping.get(
            "attack_technique",
            {}
        )

        source_decoded = source.get(
            "decoded_fields",
            {}
        )

        followup_decoded = followup.get(
            "decoded_fields",
            {}
        )

        # =====================================================
        # EVENT IDENTIFIERS
        # =====================================================

        source_event_id = (
            source_decoded.get(
                "id"
            )
            or source.get("id")
            or source_decoded.get(
                "rule",
                {}
            ).get("id")
            or "N/A"
        )

        followup_event_id = (
            followup_decoded.get(
                "id"
            )
            or followup.get("id")
            or followup_decoded.get(
                "rule",
                {}
            ).get("id")
            or "N/A"
        )

        # =====================================================
        # DISPLAY
        # =====================================================

        print()

        print(
            "=" * 80
        )

        print(
            "[WAZUH → MITRE ATT&CK] "
            "CORRELATION MATCH"
        )

        print(
            "=" * 80
        )

        # -----------------------------------------------------
        # Mapping information
        # -----------------------------------------------------

        print(
            f"Mapping ID       : "
            f"{mapping.get('mapping_id', 'N/A')}"
        )

        print(
            f"Mapping Type     : "
            f"semantic_correlation"
        )

        print()

        # -----------------------------------------------------
        # MITRE technique
        # -----------------------------------------------------

        print(
            "MITRE Technique:"
        )

        print(
            f"  Technique ID   : "
            f"{technique.get('technique_id', 'N/A')}"
        )

        print(
            f"  Technique Name : "
            f"{technique.get('technique_name', 'N/A')}"
        )

        print(
            f"  Tactic         : "
            f"{technique.get('tactic', 'N/A')}"
        )

        print(
            f"  Confidence     : "
            f"{float(mapping.get('confidence_score', 0.5)):.4f}"
        )

        # -----------------------------------------------------
        # Correlation configuration
        # -----------------------------------------------------

        print()

        print(
            "Correlation:"
        )

        print(
            f"  Relationship   : "
            f"{correlation.get('relationship', 'N/A')}"
        )

        print(
            f"  Time Window    : "
            f"{correlation.get('time_window_seconds', 'N/A')}s"
        )

        print(
            f"  Context Fields : "
            f"{', '.join(correlation.get('context_fields', [])) or 'None'}"
        )

        # =====================================================
        # SOURCE EVENT
        # =====================================================

        print()

        print(
            "SOURCE EVENT"
        )

        print(
            "-" * 80
        )

        print(
            f"  Event ID       : "
            f"{source_event_id}"
        )

        print(
            f"  Wazuh ID       : "
            f"{source.get('id', 'N/A')}"
        )

        print(
            f"  Timestamp      : "
            f"{source_decoded.get('timestamp', 'N/A')}"
        )

        print(
            f"  Decoder        : "
            f"{source_decoded.get('decoder', {}).get('name', 'N/A')}"
        )

        print(
            f"  Agent          : "
            f"{source_decoded.get('agent', {}).get('name', 'N/A')}"
        )

        print(
            f"  Agent IP       : "
            f"{source_decoded.get('agent', {}).get('ip', 'N/A')}"
        )

        print(
            f"  Source IP      : "
            f"{source_decoded.get('data', {}).get('srcip', 'N/A')}"
        )

        print(
            f"  Command        : "
            f"{source_decoded.get('data', {}).get('audit', {}).get('command', 'N/A')}"
        )

        print(
            f"  Executable     : "
            f"{source_decoded.get('data', {}).get('audit', {}).get('exe', 'N/A')}"
        )

        print(
            f"  Session        : "
            f"{source_decoded.get('data', {}).get('audit', {}).get('session', 'N/A')}"
        )

        # =====================================================
        # FOLLOW-UP EVENT
        # =====================================================

        print()

        print(
            "FOLLOW-UP EVENT"
        )

        print(
            "-" * 80
        )

        print(
            f"  Event ID       : "
            f"{followup_event_id}"
        )

        print(
            f"  Wazuh ID       : "
            f"{followup.get('id', 'N/A')}"
        )

        print(
            f"  Timestamp      : "
            f"{followup_decoded.get('timestamp', 'N/A')}"
        )

        print(
            f"  Decoder        : "
            f"{followup_decoded.get('decoder', {}).get('name', 'N/A')}"
        )

        print(
            f"  Agent          : "
            f"{followup_decoded.get('agent', {}).get('name', 'N/A')}"
        )

        print(
            f"  Agent IP       : "
            f"{followup_decoded.get('agent', {}).get('ip', 'N/A')}"
        )

        print(
            f"  Source IP      : "
            f"{followup_decoded.get('data', {}).get('srcip', 'N/A')}"
        )

        print(
            f"  Command        : "
            f"{followup_decoded.get('data', {}).get('audit', {}).get('command', 'N/A')}"
        )

        print(
            f"  Executable     : "
            f"{followup_decoded.get('data', {}).get('audit', {}).get('exe', 'N/A')}"
        )

        print(
            f"  Session        : "
            f"{followup_decoded.get('data', {}).get('audit', {}).get('session', 'N/A')}"
        )

        # =====================================================
        # EVIDENCE
        # =====================================================

        print()

        print(
            "CORRELATION EVIDENCE"
        )

        print(
            "-" * 80
        )

        if evidence:

            for item in evidence:

                print(
                    f"  ✓ {item}"
                )

        else:

            print(
                "  ✓ Source and follow-up "
                "events satisfied correlation conditions"
            )

        print()

        print(
            "=" * 80
        )