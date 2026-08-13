from datetime import datetime, timezone

from .correlationEngine import CorrelationEngine


# ============================================================
# TIMESTAMP EXTRACTION
# ============================================================

def extract_event_timestamp(event):

    fields = event.get(
        "decoded_fields",
        {}
    )

    candidates = [

        fields.get("zeek.ts"),

        fields.get("ssh.ts"),

        fields.get("conn.ts"),

        fields.get("dns.ts"),

        fields.get("http.ts"),

        fields.get("ssl.ts"),

        fields.get("ts"),

        event.get("timestamp")

    ]

    for value in candidates:

        if value is None:
            continue

        # Already numeric
        if isinstance(
            value,
            (int, float)
        ):

            return float(value)

        # Numeric string
        try:

            return float(value)

        except (
            TypeError,
            ValueError
        ):
            pass

        # ISO timestamp
        if isinstance(
            value,
            str
        ):

            try:

                normalized = value.replace(
                    "Z",
                    "+00:00"
                )

                dt = datetime.fromisoformat(
                    normalized
                )

                return dt.timestamp()

            except (
                ValueError,
                TypeError
            ):

                continue

    return None


# ============================================================
# GET LOG TYPE
# ============================================================

def get_event_log_type(event):

    return event.get(
        "log_type"
    )


# ============================================================
# GET NEEDED LOGS
# ============================================================

def get_needed_logs(
    event,
    all_events,
    mapping
):
    """
    Collect events required by a correlation mapping.

    The mapping determines:

        - log type
        - time window

    The event determines:

        - center timestamp

    Example:

        event timestamp = 1000
        window = 60

        accepted range:

            940 <= event.ts <= 1060
    """

    correlation_rule = mapping.get(
        "correlation_rule",
        {}
    )

    window_seconds = correlation_rule.get(
        "window_seconds",
        60
    )

    try:

        window_seconds = float(
            window_seconds
        )

    except (
        TypeError,
        ValueError
    ):

        window_seconds = 60.0

    center_timestamp = (
        extract_event_timestamp(
            event
        )
    )

    if center_timestamp is None:

        return []

    mapping_log_type = mapping.get(
        "log_type"
    )

    if isinstance(
        mapping_log_type,
        str
    ):

        required_log_types = {
            mapping_log_type
        }

    elif isinstance(
        mapping_log_type,
        list
    ):

        required_log_types = set(
            mapping_log_type
        )

    else:

        required_log_types = set()

    needed_logs = []

    for candidate in all_events:

        candidate_log_type = (
            get_event_log_type(
                candidate
            )
        )

        # ----------------------------------------------------
        # Filter log type
        # ----------------------------------------------------

        if required_log_types:

            if candidate_log_type not in (
                required_log_types
            ):

                continue

        # ----------------------------------------------------
        # Extract candidate timestamp
        # ----------------------------------------------------

        candidate_timestamp = (
            extract_event_timestamp(
                candidate
            )
        )

        if candidate_timestamp is None:

            continue

        # ----------------------------------------------------
        # Time difference
        # ----------------------------------------------------

        difference = abs(
            candidate_timestamp
            - center_timestamp
        )

        if difference <= window_seconds:

            needed_logs.append(
                candidate
            )

    # --------------------------------------------------------
    # Sort chronologically
    # --------------------------------------------------------

    needed_logs.sort(
        key=lambda candidate:
            extract_event_timestamp(
                candidate
            ) or 0
    )

    return needed_logs


# ============================================================
# RUN CORRELATION
# ============================================================
from .correlationEngine import CorrelationEngine
from .correlation_helpers import get_needed_logs


def correlate_zeek_events(
    event,
    all_events,
    mapping
):

    correlation_rule = mapping.get(
        "correlation_rule",
        {}
    )

    events = get_needed_logs(
        event,
        all_events,
        mapping
    )

    if not events:

        return {
            "detected": False,
            "results": []
        }

    engine = CorrelationEngine()

    return engine.correlate(
        events,
        correlation_rule
    )