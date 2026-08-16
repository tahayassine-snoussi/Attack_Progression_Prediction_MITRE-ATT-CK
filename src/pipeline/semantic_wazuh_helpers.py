from typing import Any, Dict


def get_nested_field(data: dict, path: str) -> Any:
    """Resolve dot-notation path inside a nested dict. Returns None if any segment is missing."""
    parts = path.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _coerce_equal(a, b) -> bool:
    """Compare two values, with string fallback for numeric strings vs ints."""
    if a == b:
        return True
    try:
        return str(a).strip() == str(b).strip()
    except Exception:
        return False


def _evaluate_condition(actual, operator: str, expected) -> bool:
    """Evaluate a single leaf condition."""
    op = operator.strip().lower()

    if op == "is_null":
        return actual is None

    if actual is None:
        return False

    if op == "==":
        return _coerce_equal(actual, expected)

    if op == "!=":
        return not _coerce_equal(actual, expected)

    if op == "in":
        if isinstance(expected, (list, tuple, set)):
            return any(_coerce_equal(actual, e) for e in expected)
        if isinstance(expected, str) and isinstance(actual, str):
            return actual in expected
        return False

    if op == "not_in":
        if isinstance(expected, (list, tuple, set)):
            return not any(_coerce_equal(actual, e) for e in expected)
        if isinstance(expected, str) and isinstance(actual, str):
            return actual not in expected
        return True

    if op == "contains":
        # String substring (case-insensitive) OR list membership
        if isinstance(actual, str) and isinstance(expected, str):
            return expected.lower() in actual.lower()
        if isinstance(actual, (list, tuple, set)):
            return any(_coerce_equal(expected, item) for item in actual)
        return False

    if op == "startswith":
        if isinstance(actual, str) and isinstance(expected, str):
            return actual.lower().startswith(expected.lower())
        return False

    if op == "endswith":
        if isinstance(actual, str) and isinstance(expected, str):
            return actual.lower().endswith(expected.lower())
        return False

    if op in (">", ">=", "<", "<="):
        try:
            a = float(actual)
            e = float(expected)
            if op == ">":
                return a > e
            if op == ">=":
                return a >= e
            if op == "<":
                return a < e
            if op == "<=":
                return a <= e
        except (TypeError, ValueError):
            return False

    return False


def evaluate_semantic_conditions(decoded_fields: dict, conditions_block: dict) -> bool:
    """
    Recursively evaluate AND/OR semantic condition trees against decoded_fields.
    """
    if not conditions_block:
        return True

    logic = conditions_block.get("logic", "AND")
    conditions = conditions_block.get("conditions", [])
    results = []

    for cond in conditions:
        # Nested logic block
        if "conditions" in cond:
            results.append(evaluate_semantic_conditions(decoded_fields, cond))
            continue

        field = cond.get("field")
        operator = cond.get("operator", "==")
        expected = cond.get("value")
        actual = get_nested_field(decoded_fields, field) if field else None
        results.append(_evaluate_condition(actual, operator, expected))

    if logic == "AND":
        return all(results)
    return any(results)