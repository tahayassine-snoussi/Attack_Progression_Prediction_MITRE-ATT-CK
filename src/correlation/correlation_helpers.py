from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


# ============================================================
# TIMESTAMP PARSING
# ============================================================

def parse_timestamp(
    timestamp: Any
):
    """
    Convert supported timestamp formats into
    timezone-aware UTC datetime objects.
    """

    if timestamp is None:
        return None

    # --------------------------------------------------------
    # Already datetime
    # --------------------------------------------------------

    if isinstance(timestamp, datetime):

        if timestamp.tzinfo is None:
            return timestamp.replace(
                tzinfo=timezone.utc
            )

        return timestamp.astimezone(
            timezone.utc
        )

    # --------------------------------------------------------
    # Unix timestamp
    # --------------------------------------------------------

    if isinstance(
        timestamp,
        (int, float)
    ):

        try:
            return datetime.fromtimestamp(
                float(timestamp),
                tz=timezone.utc
            )

        except (
            TypeError,
            ValueError,
            OverflowError
        ):

            return None

    # --------------------------------------------------------
    # String
    # --------------------------------------------------------

    if isinstance(
        timestamp,
        str
    ):

        timestamp = timestamp.strip()

        if not timestamp:
            return None

        # Numeric string
        try:

            numeric_timestamp = float(
                timestamp
            )

            return datetime.fromtimestamp(
                numeric_timestamp,
                tz=timezone.utc
            )

        except (
            TypeError,
            ValueError,
            OverflowError
        ):

            pass

        # ISO timestamp
        try:

            normalized = timestamp.replace(
                "Z",
                "+00:00"
            )

            parsed = datetime.fromisoformat(
                normalized
            )

            if parsed.tzinfo is None:

                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(
                timezone.utc
            )

        except (
            ValueError,
            TypeError
        ):

            return None

    return None


# ============================================================
# EVENT TIMESTAMP
# ============================================================

def extract_event_timestamp(
    event: Dict[str, Any]
):
    """
    Extract the normalized event timestamp.

    The normalized event timestamp is preferred.
    Zeek-specific timestamp fields are used as fallback.
    """

    fields = event.get(
        "decoded_fields",
        {}
    )

    candidates = [

        event.get(
            "timestamp"
        ),

        fields.get(
            "zeek.ts"
        ),

        fields.get(
            "conn.ts"
        ),

        fields.get(
            "dns.ts"
        ),

        fields.get(
            "http.ts"
        ),

        fields.get(
            "ssl.ts"
        ),

        fields.get(
            "ssh.ts"
        ),

        fields.get(
            "ts"
        )

    ]

    for value in candidates:

        parsed = parse_timestamp(
            value
        )

        if parsed is not None:
            return parsed

    return None


# ============================================================
# GET LOG TYPE
# ============================================================

def get_event_log_type(
    event: Dict[str, Any]
):
    return event.get(
        "log_type"
    )


# ============================================================
# GET MAPPING LOG TYPES
# ============================================================

def get_mapping_log_types(
    mapping: Dict[str, Any]
):
    """
    Return the log types required by a correlation mapping.

    Supports:

        "conn.log"

    and:

        [
            "conn.log",
            "dns.log"
        ]

    Empty result means the mapping does not explicitly
    restrict log types.
    """

    log_type = mapping.get(
        "log_type"
    )

    if isinstance(
        log_type,
        str
    ):

        return {
            log_type
        }

    if isinstance(
        log_type,
        list
    ):

        return {
            item
            for item in log_type
            if isinstance(
                item,
                str
            )
        }

    return set()


# ============================================================
# FILTER EVENTS FOR MAPPING
# ============================================================

def filter_events_for_mapping(
    events: List[Dict[str, Any]],
    mapping: Dict[str, Any]
):
    """
    Select only events relevant to a correlation mapping.

    Filtering is performed using the mapping's log_type.

    This happens BEFORE temporal grouping.
    """

    target_log_types = get_mapping_log_types(
        mapping
    )

    if not target_log_types:
        return list(events)

    filtered = []

    for event in events:

        if get_event_log_type(event) in target_log_types:

            filtered.append(
                event
            )

    return filtered


# ============================================================
# CREATE TEMPORAL GROUPS
# ============================================================

def create_time_groups(
    events: List[Dict[str, Any]],
    window_seconds: float
):
    """
    Create non-overlapping temporal groups.

    Example:

        window_seconds = 60

        10:00:01
        10:00:05
        10:00:20
        10:00:40

    become one group.

    If the next event is more than 60 seconds from
    the START of the current group, a new group begins.

    This is deliberately NOT a sliding window.

    That prevents the same behavior from being evaluated
    repeatedly for every individual event.
    """

    if not events:
        return []

    try:

        window_seconds = float(
            window_seconds
        )

    except (
        TypeError,
        ValueError
    ):

        raise ValueError(
            "window_seconds must be numeric"
        )

    if window_seconds <= 0:

        raise ValueError(
            "window_seconds must be greater than zero"
        )

    timestamped_events = []

    for event in events:

        timestamp = extract_event_timestamp(
            event
        )

        if timestamp is None:
            continue

        timestamped_events.append(
            (
                timestamp,
                event
            )
        )

    timestamped_events.sort(
        key=lambda item: item[0]
    )

    if not timestamped_events:
        return []

    groups = []

    current_group = []

    group_start_time = None

    for timestamp, event in timestamped_events:

        # ----------------------------------------------------
        # Start first group
        # ----------------------------------------------------

        if not current_group:

            current_group = [
                event
            ]

            group_start_time = timestamp

            continue

        elapsed = (
            timestamp
            - group_start_time
        ).total_seconds()

        # ----------------------------------------------------
        # Event belongs to current group
        # ----------------------------------------------------

        if elapsed <= window_seconds:

            current_group.append(
                event
            )

        # ----------------------------------------------------
        # Start a new group
        # ----------------------------------------------------

        else:

            groups.append(
                current_group
            )

            current_group = [
                event
            ]

            group_start_time = timestamp

    # --------------------------------------------------------
    # Last group
    # --------------------------------------------------------

    if current_group:

        groups.append(
            current_group
        )

    return groups


# ============================================================
# FIELD EXTRACTION
# ============================================================

def get_event_field(
    event: Dict[str, Any],
    field: str
):
    """
    Extract fields from the normalized Zeek event.

    Supports:

        decoded_fields["conn.id.orig_h"]

    and nested dictionaries.
    """

    decoded_fields = event.get(
        "decoded_fields",
        {}
    )

    if field in decoded_fields:

        return decoded_fields[
            field
        ]

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


# ============================================================
# BUILD GROUP KEY
# ============================================================

def build_group_key(
    event: Dict[str, Any],
    group_by: List[str]
):
    """
    Build a grouping key from rule-defined fields.

    Example:

        group_by = [
            "conn.id.orig_h"
        ]

    produces:

        ("192.168.56.20",)

    Multiple fields are supported:

        [
            "conn.id.orig_h",
            "conn.id.resp_h",
            "conn.id.resp_p"
        ]

    produces:

        (
            "192.168.56.20",
            "192.168.56.30",
            445
        )
    """

    if not group_by:

        return ()

    return tuple(
        get_event_field(
            event,
            field
        )
        for field in group_by
    )


# ============================================================
# GROUP EVENTS BY RULE
# ============================================================

def group_events_by_rule(
    events: List[Dict[str, Any]],
    mapping: Dict[str, Any]
):
    """
    Group events according to the correlation rule's
    group_by definition.

    The mapping remains the source of truth.

    Example:

        correlation_rule:
            group_by:
                - conn.id.orig_h

    Events from different source hosts are therefore
    evaluated independently.
    """

    correlation_rule = mapping.get(
        "correlation_rule",
        {}
    )

    group_by = correlation_rule.get(
        "group_by",
        []
    )

    if not isinstance(
        group_by,
        list
    ):

        raise ValueError(
            "correlation_rule.group_by must be a list"
        )

    groups: Dict[
        Tuple[Any, ...],
        List[Dict[str, Any]]
    ] = {}

    for event in events:

        key = build_group_key(
            event,
            group_by
        )

        if key not in groups:

            groups[key] = []

        groups[key].append(
            event
        )

    return groups


# ============================================================
# CREATE CORRELATION GROUPS
# ============================================================

def create_correlation_groups(
    events: List[Dict[str, Any]],
    mapping: Dict[str, Any]
):
    """
    Main grouping layer.

    Pipeline:

        1. Filter events by mapping log type
        2. Read window_seconds from mapping
        3. Create temporal groups
        4. Apply rule-defined group_by

    Returns:

        [
            {
                "time_group_id": 0,
                "group_key": (...),
                "events": [...]
            }
        ]
    """

    correlation_rule = mapping.get(
        "correlation_rule",
        {}
    )

    window_seconds = correlation_rule.get(
        "window_seconds"
    )

    if window_seconds is None:

        raise ValueError(
            "Correlation mapping is missing "
            "'correlation_rule.window_seconds'"
        )

    try:

        window_seconds = float(
            window_seconds
        )

    except (
        TypeError,
        ValueError
    ):

        raise ValueError(
            "correlation_rule.window_seconds "
            "must be numeric"
        )

    if window_seconds <= 0:

        raise ValueError(
            "correlation_rule.window_seconds "
            "must be greater than zero"
        )

    # --------------------------------------------------------
    # STEP 1
    # Filter events relevant to this mapping.
    # --------------------------------------------------------

    mapping_events = filter_events_for_mapping(
        events,
        mapping
    )

    if not mapping_events:
        return []

    # --------------------------------------------------------
    # STEP 2
    # Temporal grouping.
    # --------------------------------------------------------

    time_groups = create_time_groups(
        mapping_events,
        window_seconds
    )

    correlation_groups = []

    # --------------------------------------------------------
    # STEP 3
    # Entity/rule grouping.
    # --------------------------------------------------------

    for time_group_id, time_group in enumerate(
        time_groups
    ):

        entity_groups = group_events_by_rule(
            time_group,
            mapping
        )

        for group_key, group_events in entity_groups.items():

            correlation_groups.append({

                "time_group_id":
                    time_group_id,

                "group_key":
                    group_key,

                "events":
                    group_events

            })

    return correlation_groups


# ============================================================
# LEGACY COMPATIBILITY FUNCTION
# ============================================================

def get_needed_logs(
    event: Dict[str, Any],
    all_events: List[Dict[str, Any]],
    mapping: Dict[str, Any]
):
    """
    Compatibility helper.

    This function is retained so older code does not immediately
    break.

    New correlation code should use:

        create_correlation_groups()

    instead.

    It returns events around the supplied event using the
    mapping's correlation window.
    """

    correlation_rule = mapping.get(
        "correlation_rule",
        {}
    )

    window_seconds = correlation_rule.get(
        "window_seconds"
    )

    if window_seconds is None:

        raise ValueError(
            "Correlation mapping is missing "
            "'correlation_rule.window_seconds'"
        )

    try:

        window_seconds = float(
            window_seconds
        )

    except (
        TypeError,
        ValueError
    ):

        raise ValueError(
            "correlation_rule.window_seconds "
            "must be numeric"
        )

    event_time = extract_event_timestamp(
        event
    )

    if event_time is None:
        return []

    target_log_types = get_mapping_log_types(
        mapping
    )

    needed_logs = []

    for candidate in all_events:

        if target_log_types:

            if get_event_log_type(candidate) not in target_log_types:
                continue

        candidate_time = extract_event_timestamp(
            candidate
        )

        if candidate_time is None:
            continue

        elapsed = abs(
            (
                candidate_time
                - event_time
            ).total_seconds()
        )

        if elapsed <= window_seconds:

            needed_logs.append(
                candidate
            )

    needed_logs.sort(
        key=lambda candidate: (
            extract_event_timestamp(
                candidate
            )
            or datetime.min.replace(
                tzinfo=timezone.utc
            )
        )
    )

    return needed_logs