from __future__ import annotations

import json

from dataclasses import dataclass, asdict
from collections import defaultdict
from typing import Any


# ============================================================
# RESULT
# ============================================================

@dataclass
class SemanticMatchResult:

    matched: bool

    mapping_id: str | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None

    confidence_score: float = 0.0
    score: float = 0.0

    context_boost: float = 0.0

    context_matched: int = 0
    context_total: int = 0

    matched_conditions: list | None = None
    context_conditions: list | None = None

    reason: str | None = None

    def to_dict(self):
        return asdict(self)


# ============================================================
# ENGINE
# ============================================================

class ZeekSemanticMappingEngine:

    def __init__(self, mapping_path):

        self.mapping_path = mapping_path

        self.mappings = []

        self.index = defaultdict(list)

        self.load_database()
        self.build_indexes()

    # ========================================================
    # DATABASE
    # ========================================================

    def load_database(self):

        with open(
            self.mapping_path,
            "r",
            encoding="utf-8"
        ) as f:

            database = json.load(f)

        if isinstance(database, list):

            self.mappings = database

        elif isinstance(database, dict):

            self.mappings = database.get(
                "mappings",
                []
            )

        else:

            raise ValueError(
                "Invalid Zeek mapping database format"
            )

    # ========================================================
    # INDEX
    # ========================================================

    def build_indexes(self):

        self.index.clear()

        for mapping in self.mappings:

            log_type = mapping.get("log_type")

            if isinstance(log_type, str):

                log_types = [log_type]

            elif isinstance(log_type, list):

                log_types = log_type

            else:

                continue

            for log in log_types:

                if log:

                    self.index[log].append(mapping)

    # ========================================================
    # CANDIDATES
    # ========================================================

    def get_candidate_mappings(self, event):

        log_type = event.get("log_type")

        return self.index.get(
            log_type,
            []
        )

    # ========================================================
    # REQUIRED FIELDS
    # ========================================================

    def validate_required_fields(
        self,
        event,
        mapping
    ):

        fields = event.get(
            "decoded_fields",
            {}
        )

        semantic_conditions = mapping.get(
            "semantic_conditions",
            {}
        )

        for required_field in mapping.get(
            "required_fields",
            []
        ):

            if required_field not in fields:

                return (
                    False,
                    f"missing_required_field:{required_field}"
                )

            if fields[required_field] is None:

                if self.condition_requires_field(
                    semantic_conditions,
                    required_field
                ):

                    return (
                        False,
                        f"null_required_field:{required_field}"
                    )

        return True, None

    # ========================================================
    # CONDITION FIELD CHECK
    # ========================================================

    def condition_requires_field(
        self,
        node,
        field
    ):

        if not isinstance(node, dict):

            return False

        if "field" in node:

            return node.get("field") == field

        conditions = node.get(
            "conditions",
            []
        )

        for condition in conditions:

            if self.condition_requires_field(
                condition,
                field
            ):

                return True

        return False

    # ========================================================
    # LEAF CONDITION
    # ========================================================

    def evaluate_leaf(
        self,
        condition,
        fields
    ):

        field = condition.get("field")
        operator = condition.get("operator")
        expected = condition.get("value")

        if (
            field not in fields
            or fields[field] is None
        ):

            if operator == "is_null":

                return (
                    expected is True
                    or expected is None
                )

            return "null_field"

        actual = fields[field]

        if operator == "==":

            return actual == expected

        if operator == "!=":

            return actual != expected

        if operator == ">":

            try:
                return actual > expected
            except (TypeError, ValueError):
                return False

        if operator == ">=":

            try:
                return actual >= expected
            except (TypeError, ValueError):
                return False

        if operator == "<":

            try:
                return actual < expected
            except (TypeError, ValueError):
                return False

        if operator == "<=":

            try:
                return actual <= expected
            except (TypeError, ValueError):
                return False

        if operator == "in":

            if not isinstance(
                expected,
                (list, tuple, set)
            ):

                raise ValueError(
                    "'in' operator requires a list, tuple, or set"
                )

            return actual in expected

        if operator == "contains":

            if not isinstance(actual, str):

                return False

            return str(expected) in actual

        if operator == "startswith":

            if not isinstance(actual, str):

                return False

            return actual.startswith(
                str(expected)
            )

        if operator == "endswith":

            if not isinstance(actual, str):

                return False

            return actual.endswith(
                str(expected)
            )

        if operator == "is_null":

            return expected is False

        raise ValueError(
            f"Unsupported operator: {operator}"
        )

    # ========================================================
    # RECURSIVE CONDITIONS
    # ========================================================

    def evaluate_conditions(
        self,
        node,
        fields,
        matched_conditions=None
    ):

        if matched_conditions is None:

            matched_conditions = []

        if not isinstance(node, dict):

            return False

        if "logic" in node:

            logic = node["logic"].upper()

            children = node.get(
                "conditions",
                []
            )

            results = []

            for child in children:

                result = self.evaluate_conditions(
                    child,
                    fields,
                    matched_conditions
                )

                results.append(result)

            if logic == "AND":

                if not results:
                    return False

                if any(
                    result is False
                    for result in results
                ):
                    return False

                if any(
                    result == "null_field"
                    for result in results
                ):
                    return False

                return True

            if logic == "OR":

                return any(
                    result is True
                    for result in results
                )

            raise ValueError(
                f"Unsupported logic: {logic}"
            )

        result = self.evaluate_leaf(
            node,
            fields
        )

        if result is True:

            matched_conditions.append(node)

        return result

    # ========================================================
    # EXTERNAL CONTEXT
    # ========================================================

    def evaluate_external_context(
        self,
        event,
        external_context,
        context_provider
    ):

        result = {
            "available": context_provider is not None,
            "matched": 0,
            "total": 0,
            "boost": 0.0,
            "conditions": []
        }

        if not external_context:

            return result

        conditions = external_context.get(
            "conditions",
            []
        )

        result["total"] = len(conditions)

        if context_provider is None:

            for condition in conditions:

                result["conditions"].append({

                    "context":
                        condition.get("context"),

                    "available":
                        False,

                    "matched":
                        False,

                    "actual":
                        None,

                    "expected":
                        condition.get("value"),

                    "operator":
                        condition.get("operator"),

                    "boost":
                        0.0,

                    "reason":
                        "context_provider_unavailable"
                })

            return result

        for condition in conditions:

            context_key = condition.get(
                "context"
            )

            actual_value = context_provider.resolve(
                context_key,
                event
            )

            if actual_value is None:

                result["conditions"].append({

                    "context":
                        context_key,

                    "available":
                        False,

                    "matched":
                        False,

                    "actual":
                        None,

                    "expected":
                        condition.get("value"),

                    "operator":
                        condition.get("operator"),

                    "boost":
                        0.0,

                    "reason":
                        "context_unavailable"
                })

                continue

            matched = self.evaluate_context_condition(
                condition,
                actual_value
            )

            boost = 0.0

            if matched:

                boost = max(
                    0.0,
                    self.to_float(
                        condition.get(
                            "confidence_boost",
                            0.0
                        )
                    )
                )

                result["matched"] += 1
                result["boost"] += boost

            result["conditions"].append({

                "context":
                    context_key,

                "available":
                    True,

                "matched":
                    matched,

                "actual":
                    actual_value,

                "expected":
                    condition.get("value"),

                "operator":
                    condition.get("operator"),

                "boost":
                    boost
            })

        return result

    # ========================================================
    # MATCH ONE MAPPING
    # ========================================================

    def match_mapping(
        self,
        event,
        mapping,
        context_provider=None
    ):

        # ----------------------------------------------------
        # CORRELATION MAPPINGS ARE NOT SEMANTIC
        # ----------------------------------------------------

        if mapping.get(
            "correlation_required",
            False
        ):

            return SemanticMatchResult(
                matched=False,
                mapping_id=mapping.get("mapping_id"),
                reason="correlation_required"
            )

        # ----------------------------------------------------
        # REQUIRED FIELDS
        # ----------------------------------------------------

        valid, reason = (
            self.validate_required_fields(
                event,
                mapping
            )
        )

        if not valid:

            return SemanticMatchResult(
                matched=False,
                mapping_id=mapping.get("mapping_id"),
                reason=reason
            )

        # ----------------------------------------------------
        # SEMANTIC CONDITIONS
        # ----------------------------------------------------

        fields = event.get(
            "decoded_fields",
            {}
        )

        semantic_conditions = mapping.get(
            "semantic_conditions"
        )

        if not semantic_conditions:

            return SemanticMatchResult(
                matched=False,
                mapping_id=mapping.get("mapping_id"),
                reason="no_semantic_conditions"
            )

        matched_conditions = []

        semantic_result = self.evaluate_conditions(
            semantic_conditions,
            fields,
            matched_conditions
        )

        if semantic_result is not True:

            return SemanticMatchResult(
                matched=False,
                mapping_id=mapping.get("mapping_id"),
                reason="semantic_conditions_failed"
            )

        # ----------------------------------------------------
        # BASE CONFIDENCE
        # ----------------------------------------------------

        base_confidence = min(
            1.0,
            max(
                0.0,
                self.to_float(
                    mapping.get(
                        "confidence_score",
                        0.0
                    )
                )
            )
        )

        # ----------------------------------------------------
        # EXTERNAL CONTEXT
        # ----------------------------------------------------

        context_result = (
            self.evaluate_external_context(
                event,
                mapping.get(
                    "external_context"
                ),
                context_provider
            )
        )

        # ----------------------------------------------------
        # FINAL SCORE
        # ----------------------------------------------------

        final_score = min(
            1.0,
            base_confidence
            + context_result["boost"]
        )

        technique = mapping.get(
            "attack_technique",
            {}
        )

        return SemanticMatchResult(

            matched=True,

            mapping_id=mapping.get(
                "mapping_id"
            ),

            technique_id=technique.get(
                "technique_id"
            ),

            technique_name=technique.get(
                "technique_name"
            ),

            tactic=technique.get(
                "tactic"
            ),

            confidence_score=round(
                base_confidence,
                4
            ),

            score=round(
                final_score,
                4
            ),

            context_boost=round(
                context_result["boost"],
                4
            ),

            context_matched=
                context_result["matched"],

            context_total=
                context_result["total"],

            matched_conditions=
                matched_conditions,

            context_conditions=
                context_result["conditions"],

            reason="semantic_match"
        )

    # ========================================================
    # MAP ONE EVENT
    # ========================================================

    def map_event(
        self,
        event,
        context_provider=None
    ):

        results = []

        candidates = self.get_candidate_mappings(
            event
        )

        for mapping in candidates:

            result = self.match_mapping(
                event,
                mapping,
                context_provider
            )

            if result.matched:

                results.append(result)

        results.sort(
            key=lambda result:
                result.score,
            reverse=True
        )

        return results

    # ========================================================
    # MAP MANY EVENTS
    # ========================================================

    def map_events(
        self,
        events,
        context_provider=None
    ):

        results = []

        for event in events:

            matches = self.map_event(
                event,
                context_provider
            )

            # -----------------------------------------------
            # IMPORTANT:
            # DO NOT PRINT OR STORE EMPTY EVENTS
            # -----------------------------------------------

            if not matches:
                continue

            results.append({

                "event":
                    event,

                "matches": [
                    result.to_dict()
                    for result in matches
                ]
            })

        return results

    # ========================================================
    # CONTEXT CONDITION
    # ========================================================

    def evaluate_context_condition(
        self,
        condition,
        actual_value
    ):

        operator = condition.get(
            "operator"
        )

        expected = condition.get(
            "value"
        )

        if operator == "==":

            return actual_value == expected

        if operator == "!=":

            return actual_value != expected

        if operator == "in":

            if not isinstance(
                expected,
                (list, tuple, set)
            ):

                raise ValueError(
                    "'in' operator requires a list, tuple, or set"
                )

            return actual_value in expected

        if operator == ">":

            try:
                return actual_value > expected
            except (TypeError, ValueError):
                return False

        if operator == ">=":

            try:
                return actual_value >= expected
            except (TypeError, ValueError):
                return False

        if operator == "<":

            try:
                return actual_value < expected
            except (TypeError, ValueError):
                return False

        if operator == "<=":

            try:
                return actual_value <= expected
            except (TypeError, ValueError):
                return False

        raise ValueError(
            "Unsupported external context "
            f"operator: {operator}"
        )

    # ========================================================
    # HELPER
    # ========================================================

    @staticmethod
    def to_float(value):

        try:
            return float(value)

        except (
            TypeError,
            ValueError
        ):

            return 0.0