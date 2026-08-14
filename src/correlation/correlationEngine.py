from __future__ import annotations

import math
import ipaddress

from collections import defaultdict
from datetime import datetime, timezone
from statistics import mean, stdev
from typing import Any, Dict, List, Tuple


class CorrelationEngine:
    """
    Generic declarative correlation engine for Zeek telemetry.

    The engine does NOT know about MITRE ATT&CK.

    It receives:

        - events
        - correlation_rule

    The correlation rule defines:

        - time window
        - grouping
        - aggregations
        - conditions
        - optional state condition
        - scoring
    """

    # ========================================================
    # SUPPORTED AGGREGATIONS
    # ========================================================

    SUPPORTED_AGGREGATIONS = {
        "count",
        "nunique",
        "mean",
        "sum",
        "min",
        "max",
        "ratio",
        "standard_deviation",
        "coefficient_of_variation",
        "entropy",
        "rate",
        "subnet_density",
    }

    # ========================================================
    # SUPPORTED OPERATORS
    # ========================================================

    SUPPORTED_OPERATORS = {
        ">",
        ">=",
        "<",
        "<=",
        "==",
        "!=",
        "in",
        "not_in",
        "is_null",
    }

    # ========================================================
    # PUBLIC API
    # ========================================================

    def correlate(
        self,
        events: List[Dict[str, Any]],
        correlation_rule: Dict[str, Any],
    ) -> Dict[str, Any]:

        validated_rule = self.validate_rule(
            correlation_rule
        )

        if not events:
            return {
                "detected": False,
                "results": []
            }

        # --------------------------------------------------------
        # IMPORTANT:
        #
        # Temporal grouping has already been performed by
        # ZeekCorrelationPipeline.
        #
        # Therefore this method evaluates the supplied events
        # as ONE correlation group.
        # --------------------------------------------------------

        grouped_events = self.group_events(
            events,
            validated_rule["group_by"]
        )

        results = []

        for group_key, group_events in grouped_events.items():

            metrics = self.calculate_metrics(
                group_events,
                validated_rule["aggregations"]
            )

            condition_results = (
                self.evaluate_conditions(
                    metrics,
                    validated_rule["conditions"]
                )
            )

            state_result = (
                self.evaluate_state_condition(
                    group_events,
                    validated_rule.get(
                        "state_condition"
                    )
                )
            )

            detected = self.evaluate_detection(
                condition_results,
                state_result
            )

            if not detected:
                continue

            score = self.calculate_score(
                validated_rule,
                condition_results,
                state_result
            )

            results.append({

                "group": group_key,

                "metrics": metrics,

                "conditions":
                    condition_results,

                "state_condition":
                    state_result,

                "score":
                    score

            })

        return {

            "detected":
                bool(results),

            "results":
                results

        }

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate_rule(
        self,
        correlation_rule: Dict[str, Any]
    ):

        if not isinstance(
            correlation_rule,
            dict
        ):

            raise TypeError(
                "correlation_rule must be a dictionary"
            )

        required_fields = [
            "window_seconds",
            "group_by",
            "aggregations",
            "conditions"
        ]

        for field in required_fields:

            if field not in correlation_rule:

                raise ValueError(
                    f"Missing correlation rule field: "
                    f"{field}"
                )

        if not isinstance(
            correlation_rule[
                "window_seconds"
            ],
            (int, float)
        ):

            raise TypeError(
                "window_seconds must be numeric"
            )

        if correlation_rule[
            "window_seconds"
        ] <= 0:

            raise ValueError(
                "window_seconds must be greater than zero"
            )

        if not isinstance(
            correlation_rule["group_by"],
            list
        ):

            raise TypeError(
                "group_by must be a list"
            )

        if not isinstance(
            correlation_rule["aggregations"],
            dict
        ):

            raise TypeError(
                "aggregations must be a dictionary"
            )

        if not isinstance(
            correlation_rule["conditions"],
            list
        ):

            raise TypeError(
                "conditions must be a list"
            )

        # ----------------------------------------------------
        # Validate aggregations
        # ----------------------------------------------------

        for (
            metric_name,
            aggregation
        ) in correlation_rule[
            "aggregations"
        ].items():

            if not isinstance(
                aggregation,
                dict
            ):

                raise TypeError(
                    f"Aggregation '{metric_name}' "
                    f"must be a dictionary"
                )

            function = aggregation.get(
                "function"
            )

            if function not in (
                self.SUPPORTED_AGGREGATIONS
            ):

                raise ValueError(
                    f"Unsupported aggregation "
                    f"'{function}' for metric "
                    f"'{metric_name}'"
                )

            if (
                function not in {
                    "count",
                    "rate"
                }
                and
                "field" not in aggregation
            ):

                raise ValueError(
                    f"Aggregation '{metric_name}' "
                    f"requires a field"
                )

        # ----------------------------------------------------
        # Validate conditions
        # ----------------------------------------------------

        for condition in correlation_rule[
            "conditions"
        ]:

            if "metric" not in condition:

                raise ValueError(
                    "Condition must contain 'metric'"
                )

            if "operator" not in condition:

                raise ValueError(
                    "Condition must contain 'operator'"
                )

            operator = condition[
                "operator"
            ]

            if operator not in (
                self.SUPPORTED_OPERATORS
            ):

                raise ValueError(
                    f"Unsupported operator: "
                    f"{operator}"
                )

            if (
                operator != "is_null"
                and
                "value" not in condition
            ):

                raise ValueError(
                    f"Condition using '{operator}' "
                    f"requires a value"
                )

        # ----------------------------------------------------
        # Validate state condition
        # ----------------------------------------------------

        state_condition = (
            correlation_rule.get(
                "state_condition"
            )
        )

        if state_condition:

            required = [
                "field",
                "values",
                "aggregation",
                "operator",
                "value"
            ]

            for field in required:

                if field not in state_condition:

                    raise ValueError(
                        f"State condition missing "
                        f"'{field}'"
                    )

            if (
                state_condition[
                    "aggregation"
                ]
                not in self.SUPPORTED_AGGREGATIONS
            ):

                raise ValueError(
                    "Unsupported state aggregation: "
                    f"{state_condition['aggregation']}"
                )

            if (
                state_condition[
                    "operator"
                ]
                not in self.SUPPORTED_OPERATORS
            ):

                raise ValueError(
                    "Unsupported state operator: "
                    f"{state_condition['operator']}"
                )

        return correlation_rule

    # ========================================================
    # TIMESTAMP HANDLING
    # ========================================================

    def parse_timestamp(
        self,
        timestamp: Any
    ):

        if timestamp is None:
            return None

        if isinstance(
            timestamp,
            datetime
        ):

            if timestamp.tzinfo is None:

                return timestamp.replace(
                    tzinfo=timezone.utc
                )

            return timestamp.astimezone(
                timezone.utc
            )

        if isinstance(
            timestamp,
            (int, float)
        ):

            return datetime.fromtimestamp(
                float(timestamp),
                tz=timezone.utc
            )

        if isinstance(
            timestamp,
            str
        ):

            timestamp = timestamp.strip()

            if not timestamp:
                return None

            # ------------------------------------------------
            # Numeric string
            # ------------------------------------------------

            try:

                return datetime.fromtimestamp(
                    float(timestamp),
                    tz=timezone.utc
                )

            except (
                TypeError,
                ValueError
            ):

                pass

            # ------------------------------------------------
            # ISO timestamp
            # ------------------------------------------------

            try:

                parsed = datetime.fromisoformat(
                    timestamp.replace(
                        "Z",
                        "+00:00"
                    )
                )

                if parsed.tzinfo is None:

                    parsed = parsed.replace(
                        tzinfo=timezone.utc
                    )

                return parsed.astimezone(
                    timezone.utc
                )

            except ValueError:

                return None

        return None

    # ========================================================
    # TIME WINDOWS
    # ========================================================

    def create_time_windows(
        self,
        events: List[Dict[str, Any]],
        window_seconds: float
    ):

        if not events:
            return []

        timestamped_events = []

        for event in events:

            event_time = self.parse_timestamp(
                event.get("timestamp")
            )

            if event_time is None:
                continue

            timestamped_events.append(
                (
                    event_time,
                    event
                )
            )

        timestamped_events.sort(
            key=lambda item: item[0]
        )

        windows = []

        # ----------------------------------------------------
        # Sliding window
        # ----------------------------------------------------

        for index, (
            start_time,
            start_event
        ) in enumerate(
            timestamped_events
        ):

            current_window = [
                start_event
            ]

            for later_time, later_event in (
                timestamped_events[
                    index + 1:
                ]
            ):

                elapsed = (
                    later_time
                    - start_time
                ).total_seconds()

                if elapsed <= window_seconds:

                    current_window.append(
                        later_event
                    )

                else:

                    break

            windows.append(
                current_window
            )

        return windows

    # ========================================================
    # FIELD EXTRACTION
    # ========================================================

    def get_field(
        self,
        event: Dict[str, Any],
        field: str
    ):

        decoded_fields = event.get(
            "decoded_fields",
            {}
        )

        # ----------------------------------------------------
        # Exact normalized field
        # ----------------------------------------------------

        if field in decoded_fields:

            return decoded_fields[
                field
            ]

        # ----------------------------------------------------
        # Nested fallback
        # ----------------------------------------------------

        current = decoded_fields

        for part in field.split("."):

            if not isinstance(
                current,
                dict
            ):

                return None

            if part not in current:

                return None

            current = current[
                part
            ]

        return current

    # ========================================================
    # GROUPING
    # ========================================================

    def group_events(
        self,
        events: List[Dict[str, Any]],
        group_by: List[str]
    ):

        grouped = defaultdict(list)

        if not group_by:

            grouped[()] = events

            return grouped

        for event in events:

            group_key = tuple(
                self.get_field(
                    event,
                    field
                )
                for field in group_by
            )

            grouped[
                group_key
            ].append(
                event
            )

        return grouped

    # ========================================================
    # METRICS
    # ========================================================

    def calculate_metrics(
        self,
        events,
        aggregations
    ):

        metrics = {}

        for (
            metric_name,
            specification
        ) in aggregations.items():

            function_name = specification[
                "function"
            ]

            function = getattr(
                self,
                f"aggregate_{function_name}"
            )

            metrics[
                metric_name
            ] = function(
                events,
                specification
            )

        return metrics

    # ========================================================
    # COUNT
    # ========================================================

    def aggregate_count(
        self,
        events,
        specification
    ):

        return len(events)

    # ========================================================
    # NUNIQUE
    # ========================================================

    def aggregate_nunique(
        self,
        events,
        specification
    ):

        field = specification[
            "field"
        ]

        values = [
            self.get_field(
                event,
                field
            )
            for event in events
        ]

        values = [
            value
            for value in values
            if value is not None
        ]

        return len(
            set(values)
        )

    # ========================================================
    # MEAN
    # ========================================================

    def aggregate_mean(
        self,
        events,
        specification
    ):

        values = self.numeric_values(
            events,
            specification["field"]
        )

        if not values:
            return None

        return mean(values)

    # ========================================================
    # SUM
    # ========================================================

    def aggregate_sum(
        self,
        events,
        specification
    ):

        values = self.numeric_values(
            events,
            specification["field"]
        )

        if not values:
            return 0

        return sum(values)

    # ========================================================
    # MIN
    # ========================================================

    def aggregate_min(
        self,
        events,
        specification
    ):

        values = self.numeric_values(
            events,
            specification["field"]
        )

        if not values:
            return None

        return min(values)

    # ========================================================
    # MAX
    # ========================================================

    def aggregate_max(
        self,
        events,
        specification
    ):

        values = self.numeric_values(
            events,
            specification["field"]
        )

        if not values:
            return None

        return max(values)

    # ========================================================
    # RATIO
    # ========================================================

    def aggregate_ratio(
        self,
        events,
        specification
    ):

        field = specification[
            "field"
        ]

        values = specification.get(
            "values",
            []
        )

        if not events:
            return 0.0

        matching = 0

        for event in events:

            value = self.get_field(
                event,
                field
            )

            if value in values:

                matching += 1

        return matching / len(events)

    # ========================================================
    # STANDARD DEVIATION
    # ========================================================

    def aggregate_standard_deviation(
        self,
        events,
        specification
    ):

        values = self.numeric_values(
            events,
            specification["field"]
        )

        if len(values) < 2:
            return 0.0

        return stdev(values)

    # ========================================================
    # COEFFICIENT OF VARIATION
    # ========================================================

    def aggregate_coefficient_of_variation(
        self,
        events,
        specification
    ):

        values = self.numeric_values(
            events,
            specification["field"]
        )

        if len(values) < 2:
            return 0.0

        average = mean(values)

        if average == 0:
            return 0.0

        return stdev(values) / abs(
            average
        )

    # ========================================================
    # ENTROPY
    # ========================================================

    def aggregate_entropy(
        self,
        events,
        specification
    ):

        field = specification[
            "field"
        ]

        values = [
            self.get_field(
                event,
                field
            )
            for event in events
        ]

        values = [
            value
            for value in values
            if value is not None
        ]

        if not values:
            return 0.0

        counts = defaultdict(int)

        for value in values:

            counts[value] += 1

        total = len(values)

        entropy = 0.0

        for count in counts.values():

            probability = (
                count / total
            )

            entropy -= (
                probability
                *
                math.log2(
                    probability
                )
            )

        return entropy

    # ========================================================
    # RATE
    # ========================================================

    def aggregate_rate(
        self,
        events,
        specification
    ):

        if not events:
            return 0.0

        window_seconds = specification.get(
            "window_seconds"
        )

        if window_seconds is None:

            return float(
                len(events)
            )

        if window_seconds <= 0:
            return 0.0

        return (
            len(events)
            /
            window_seconds
        )

    # ========================================================
    # SUBNET DENSITY
    # ========================================================

    def aggregate_subnet_density(
        self,
        events,
        specification
    ):

        field = specification[
            "field"
        ]

        subnet = specification.get(
            "subnet"
        )

        if not subnet:

            raise ValueError(
                "subnet_density requires "
                "'subnet'"
            )

        network = ipaddress.ip_network(
            subnet,
            strict=False
        )

        observed = set()

        for event in events:

            value = self.get_field(
                event,
                field
            )

            if value is None:
                continue

            try:

                ip = ipaddress.ip_address(
                    str(value)
                )

                if ip in network:

                    observed.add(ip)

            except ValueError:

                continue

        total_addresses = (
            network.num_addresses
        )

        if total_addresses == 0:
            return 0.0

        return (
            len(observed)
            /
            total_addresses
        )

    # ========================================================
    # NUMERIC VALUES
    # ========================================================

    def numeric_values(
        self,
        events,
        field
    ):

        values = []

        for event in events:

            value = self.get_field(
                event,
                field
            )

            if value is None:
                continue

            try:

                values.append(
                    float(value)
                )

            except (
                TypeError,
                ValueError
            ):

                continue

        return values

    # ========================================================
    # CONDITIONS
    # ========================================================

    def evaluate_conditions(
        self,
        metrics,
        conditions
    ):

        results = []

        for condition in conditions:

            metric_name = condition[
                "metric"
            ]

            actual_value = metrics.get(
                metric_name
            )

            operator = condition[
                "operator"
            ]

            expected_value = condition.get(
                "value"
            )

            matched = self.compare(
                actual_value,
                operator,
                expected_value
            )

            results.append({

                "metric": metric_name,

                "actual": actual_value,

                "operator": operator,

                "expected": expected_value,

                "matched": matched

            })

        return {

            "all_matched": all(
                result["matched"]
                for result in results
            ),

            "results": results

        }

    # ========================================================
    # STATE CONDITION
    # ========================================================

    def evaluate_state_condition(
        self,
        events,
        state_condition
    ):

        if not state_condition:
            return None

        field = state_condition[
            "field"
        ]

        allowed_values = state_condition[
            "values"
        ]

        aggregation = state_condition[
            "aggregation"
        ]

        operator = state_condition[
            "operator"
        ]

        expected = state_condition[
            "value"
        ]

        specification = {

            "function": aggregation,

            "field": field,

            "values": allowed_values

        }

        function = getattr(
            self,
            f"aggregate_{aggregation}"
        )

        actual = function(
            events,
            specification
        )

        matched = self.compare(
            actual,
            operator,
            expected
        )

        return {

            "field": field,

            "values": allowed_values,

            "aggregation": aggregation,

            "actual": actual,

            "operator": operator,

            "expected": expected,

            "matched": matched

        }

    # ========================================================
    # COMPARE
    # ========================================================

    def compare(
        self,
        actual,
        operator,
        expected
    ):

        if operator == "is_null":

            should_be_null = bool(
                expected
            )

            return (
                actual is None
            ) == should_be_null

        if actual is None:
            return False

        try:

            if operator == ">":
                return actual > expected

            if operator == ">=":
                return actual >= expected

            if operator == "<":
                return actual < expected

            if operator == "<=":
                return actual <= expected

            if operator == "==":
                return actual == expected

            if operator == "!=":
                return actual != expected

            if operator == "in":
                return actual in expected

            if operator == "not_in":
                return actual not in expected

        except (
            TypeError,
            ValueError
        ):

            return False

        raise ValueError(
            f"Unsupported operator: "
            f"{operator}"
        )

    # ========================================================
    # DETECTION LOGIC
    # ========================================================

    def evaluate_detection(
        self,
        condition_results,
        state_result
    ):

        conditions_match = (
            condition_results[
                "all_matched"
            ]
        )

        if state_result is None:

            return conditions_match

        return (
            conditions_match
            and
            state_result["matched"]
        )

    # ========================================================
    # SCORING
    # ========================================================

    def calculate_score(
        self,
        correlation_rule,
        condition_results,
        state_result
    ):

        scoring = correlation_rule.get(
            "scoring",
            {}
        )

        base_weight = scoring.get(
            "base_weight",
            1.0
        )

        state_weight = scoring.get(
            "state_condition_weight",
            1.0
        )

        score = base_weight

        if (
            state_result is not None
            and
            state_result["matched"]
        ):

            score *= state_weight

        return score