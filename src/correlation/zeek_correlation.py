from __future__ import annotations

from typing import Any, Dict, List

from .correlationEngine import CorrelationEngine
from .correlation_helpers import (
    create_correlation_groups
)


class ZeekCorrelationPipeline:
    """
    Executes Zeek correlation mappings.

    Architecture:

        events
            ↓
        mapping
            ↓
        temporal grouping
            ↓
        rule/entity grouping
            ↓
        CorrelationEngine
            ↓
        detection

    The correlation database remains completely separate
    from the semantic mapping database.
    """

    def __init__(
        self,
        correlation_mappings: List[Dict[str, Any]]
    ):

        self.correlation_mappings = (
            correlation_mappings
        )

        self.engine = CorrelationEngine()

    # ========================================================
    # RUN ALL CORRELATION MAPPINGS
    # ========================================================

    def process(
        self,
        events: List[Dict[str, Any]]
    ):

        if not events:
            return []

        detections = []

        for mapping in self.correlation_mappings:

            mapping_detections = (
                self.process_mapping(
                    events,
                    mapping
                )
            )

            detections.extend(
                mapping_detections
            )

        return detections

    # ========================================================
    # PROCESS ONE MAPPING
    # ========================================================

    def process_mapping(
        self,
        events: List[Dict[str, Any]],
        mapping: Dict[str, Any]
    ):

        mapping_id = mapping.get(
            "mapping_id",
            "unknown"
        )

        correlation_rule = mapping.get(
            "correlation_rule"
        )

        if not isinstance(
            correlation_rule,
            dict
        ):

            raise ValueError(
                f"Correlation mapping "
                f"'{mapping_id}' is missing "
                f"'correlation_rule'"
            )

        # ----------------------------------------------------
        # Create temporal + entity groups
        # ----------------------------------------------------

        groups = create_correlation_groups(
            events,
            mapping
        )

        if not groups:
            return []

        detections = []

        # ----------------------------------------------------
        # Evaluate each group exactly once
        # ----------------------------------------------------

        for group in groups:

            group_events = group[
                "events"
            ]

            if not group_events:
                continue

            result = self.engine.correlate(
                group_events,
                correlation_rule
            )

            if not result.get(
                "detected",
                False
            ):

                continue

            detections.append({

                "mapping_id":
                    mapping_id,

                "attack_technique":
                    mapping.get(
                        "attack_technique",
                        {}
                    ),

                "confidence_score":
                    mapping.get(
                        "confidence_score",
                        0.0
                    ),

                "time_group_id":
                    group.get(
                        "time_group_id"
                    ),

                "group_key":
                    group.get(
                        "group_key"
                    ),

                "events":
                    group_events,

                "correlation_result":
                    result

            })

        return detections