import json
from dataclasses import dataclass, asdict
from collections import defaultdict


# ============================================================
# RESULT
# ============================================================

@dataclass
class SemanticMatchResult:

    matched: bool

    mapping_id: str = None
    technique_id: str = None
    technique_name: str = None
    tactic: str = None

    confidence_score: float = 0.0
    score: float = 0.0

    matched_conditions: list = None

    context_required: bool = False

    reason: str = None

    def to_dict(self):
        return asdict(self)


# ============================================================
# ENGINE
# ============================================================

class ZeekSemanticMappingEngine:

    def __init__(self, mapping_path):

        self.mapping_path = mapping_path

        self.mappings = []

        # Index by log_type
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

        # Database is directly a list
        if isinstance(database, list):

            self.mappings = database
            return

        # Database wrapped in metadata
        if isinstance(database, dict):

            self.mappings = database.get(
                "mappings",
                []
            )

            return

        raise ValueError(
            "Invalid Zeek mapping database format"
        )

    # ========================================================
    # INDEX
    # ========================================================

    def build_indexes(self):

        for mapping in self.mappings:

            log_type = mapping.get(
                "log_type"
            )

            if isinstance(log_type, str):

                log_types = [log_type]

            elif isinstance(log_type, list):

                log_types = log_type

            else:

                continue

            for log in log_types:

                if log:

                    self.index[log].append(
                        mapping
                    )

    # ========================================================
    # CANDIDATES
    # ========================================================

    def get_candidate_mappings(self, event):

        log_type = event.get(
            "log_type"
        )

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

        for required_field in mapping.get(
            "required_fields",
            []
        ):

            # Field does not exist
            if required_field not in fields:

                return False, (
                    f"missing_required_field:"
                    f"{required_field}"
                )

            # Field exists but has None
            #
            # IMPORTANT:
            # Some Zeek fields can legitimately be null.
            #
            # Therefore we only reject None if the field
            # is actually used by a semantic condition.
            #
            # This prevents fields such as ssh.direction
            # from killing an otherwise valid semantic match.

            if fields[required_field] is None:

                semantic_conditions = mapping.get(
                    "semantic_conditions",
                    {}
                )

                if self.condition_requires_field(
                    semantic_conditions,
                    required_field
                ):

                    return False, (
                        f"null_required_field:"
                        f"{required_field}"
                    )

        return True, None

    # ========================================================
    # CHECK WHETHER A CONDITION USES A FIELD
    # ========================================================

    def condition_requires_field(
        self,
        node,
        field
    ):

        if not isinstance(node, dict):

            return False

        # Leaf condition
        if "field" in node:

            return node.get("field") == field

        # Logic group
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

        field = condition.get(
            "field"
        )

        operator = condition.get(
            "operator"
        )

        expected = condition.get(
            "value"
        )

        # ----------------------------------------------------
        # Missing field
        # ----------------------------------------------------

        if (
            field not in fields
            or fields[field] is None
        ):

            if operator == "is_null":

                if (
                    expected is True
                    or expected is None
                ):

                    return True

                return False

            return "null_field"

        actual = fields[field]

        # ----------------------------------------------------
        # Equality
        # ----------------------------------------------------

        if operator == "==":

            return actual == expected

        # ----------------------------------------------------
        # Not equal
        # ----------------------------------------------------

        if operator == "!=":

            return actual != expected

        # ----------------------------------------------------
        # Greater than
        # ----------------------------------------------------

        if operator == ">":

            return actual > expected

        # ----------------------------------------------------
        # Greater/equal
        # ----------------------------------------------------

        if operator == ">=":

            return actual >= expected

        # ----------------------------------------------------
        # Less than
        # ----------------------------------------------------

        if operator == "<":

            return actual < expected

        # ----------------------------------------------------
        # Less/equal
        # ----------------------------------------------------

        if operator == "<=":

            return actual <= expected

        # ----------------------------------------------------
        # IN
        # ----------------------------------------------------

        if operator == "in":

            if not isinstance(
                expected,
                (list, tuple, set)
            ):

                raise ValueError(
                    "'in' operator requires "
                    "a list, tuple, or set"
                )

            return actual in expected

        # ----------------------------------------------------
        # CONTAINS
        # ----------------------------------------------------

        if operator == "contains":

            if not isinstance(
                actual,
                str
            ):

                return False

            return str(expected) in actual

        # ----------------------------------------------------
        # STARTSWITH
        # ----------------------------------------------------

        if operator == "startswith":

            if not isinstance(
                actual,
                str
            ):

                return False

            return actual.startswith(
                str(expected)
            )

        # ----------------------------------------------------
        # ENDSWITH
        # ----------------------------------------------------

        if operator == "endswith":

            if not isinstance(
                actual,
                str
            ):

                return False

            return actual.endswith(
                str(expected)
            )

        # ----------------------------------------------------
        # IS NULL
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # Logic group
        # ----------------------------------------------------

        if "logic" in node:

            logic = node[
                "logic"
            ].upper()

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

                results.append(
                    result
                )

            # ------------------------------------------------
            # AND
            # ------------------------------------------------

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

            # ------------------------------------------------
            # OR
            # ------------------------------------------------

            if logic == "OR":

                if any(
                    result is True
                    for result in results
                ):

                    return True

                return False

            raise ValueError(
                f"Unsupported logic: {logic}"
            )

        # ----------------------------------------------------
        # Leaf
        # ----------------------------------------------------

        result = self.evaluate_leaf(
            node,
            fields
        )

        if result is True:

            matched_conditions.append(
                node
            )

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

        # No external context configuration
        if not external_context:

            return True

        required = external_context.get(
            "required",
            False
        )

        # ----------------------------------------------------
        # Context required but provider unavailable
        # ----------------------------------------------------

        if context_provider is None:

            if required:

                return "context_required"

            return True

        # ----------------------------------------------------
        # Evaluate context conditions
        # ----------------------------------------------------

        for condition in external_context.get(
            "conditions",
            []
        ):

            context_key = condition.get(
                "context"
            )

            operator = condition.get(
                "operator"
            )

            expected = condition.get(
                "value"
            )

            actual = context_provider.resolve(
                context_key,
                event
            )

            if actual is None:

                return False

            if operator == "==":

                if actual != expected:

                    return False

            elif operator == "!=":

                if actual == expected:

                    return False

            elif operator == "in":

                if actual not in expected:

                    return False

            else:

                raise ValueError(
                    f"Unsupported external "
                    f"context operator: {operator}"
                )

        return True

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
        # Correlation mappings don't belong here
        # ----------------------------------------------------

        if mapping.get(
            "correlation_required",
            False
        ):

            return SemanticMatchResult(
                matched=False,
                reason="correlation_required"
            )

        # ----------------------------------------------------
        # Required fields
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
                reason=reason
            )

        # ----------------------------------------------------
        # Semantic conditions
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
                reason="no_semantic_conditions"
            )

        matched_conditions = []

        semantic_result = (
            self.evaluate_conditions(
                semantic_conditions,
                fields,
                matched_conditions
            )
        )

        if semantic_result is not True:

            return SemanticMatchResult(
                matched=False,
                reason="semantic_conditions_failed"
            )

        # ----------------------------------------------------
        # External context
        # ----------------------------------------------------

        external_context = mapping.get(
            "external_context"
        )

        context_result = (
            self.evaluate_external_context(
                event,
                external_context,
                context_provider
            )
        )

        # Context required but unavailable
        if context_result == "context_required":

            technique = mapping.get(
                "attack_technique",
                {}
            )

            confidence = self.to_float(
                mapping.get(
                    "confidence_score"
                )
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

                confidence_score=confidence,

                score=confidence,

                matched_conditions=matched_conditions,

                context_required=True,

                reason=(
                    "semantic_conditions_matched_"
                    "but_external_context_required"
                )
            )

        # Context exists but failed
        if context_result is False:

            return SemanticMatchResult(
                matched=False,
                reason="external_context_failed"
            )

        # ----------------------------------------------------
        # Successful match
        # ----------------------------------------------------

        technique = mapping.get(
            "attack_technique",
            {}
        )

        confidence = self.to_float(
            mapping.get(
                "confidence_score"
            )
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

            confidence_score=confidence,

            score=confidence,

            matched_conditions=matched_conditions,

            context_required=False,

            reason="all_conditions_met"
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

            # ------------------------------------------------
            # IMPORTANT
            #
            # We keep:
            #
            # matched=True
            # context_required=True
            #
            # because the semantic evidence matched,
            # but external context is still needed.
            # ------------------------------------------------

            if result.matched:

                results.append(
                    result
                )

        # Highest confidence first
        results.sort(
            key=lambda result: result.score,
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

            results.append({

                "event": event,

                "matches": [
                    result.to_dict()
                    for result in matches
                ]

            })

        return results

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