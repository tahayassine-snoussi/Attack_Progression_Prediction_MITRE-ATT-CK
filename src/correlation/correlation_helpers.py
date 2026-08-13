from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List


def parse_timestamp(timestamp: Any):

    if timestamp is None:
        return None

    if isinstance(timestamp, datetime):
        return timestamp

    if isinstance(timestamp, (int, float)):

        return datetime.fromtimestamp(
            float(timestamp)
        )

    if isinstance(timestamp, str):

        timestamp = timestamp.strip()

        try:

            return datetime.fromisoformat(
                timestamp.replace(
                    "Z",
                    "+00:00"
                )
            )

        except ValueError:

            return None

    return None


def get_needed_logs(
    event,
    all_events,
    mapping
):

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

    target_log_type = mapping.get(
        "log_type"
    )

    # --------------------------------------------------------
    # If mapping supports multiple log types
    # --------------------------------------------------------

    if isinstance(
        target_log_type,
        str
    ):

        target_log_types = {
            target_log_type
        }

    elif isinstance(
        target_log_type,
        list
    ):

        target_log_types = set(
            target_log_type
        )

    else:

        target_log_types = set()

    event_time = parse_timestamp(
        event.get("timestamp")
    )

    if event_time is None:

        return []

    needed_logs = []

    # --------------------------------------------------------
    # Select events:
    #
    # 1. Same Zeek log type
    # 2. Inside correlation timeframe
    # --------------------------------------------------------

    for candidate in all_events:

        candidate_log_type = candidate.get(
            "log_type"
        )

        if (
            target_log_types
            and
            candidate_log_type
            not in target_log_types
        ):

            continue

        candidate_time = parse_timestamp(
            candidate.get("timestamp")
        )

        if candidate_time is None:

            continue

        elapsed = (
            candidate_time - event_time
        ).total_seconds()

        # ----------------------------------------------------
        # We use an absolute window here so events before and
        # after the triggering event can participate.
        # ----------------------------------------------------

        if abs(elapsed) <= window_seconds:

            needed_logs.append(
                candidate
            )

    return needed_logs