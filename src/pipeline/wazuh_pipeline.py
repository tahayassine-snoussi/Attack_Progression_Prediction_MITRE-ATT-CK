import json

from decoder.decoder_engine import (
    decode_wazuh_event
)

from .wazuh_mapping_engine import (
    WazuhMappingEngine
)


# =========================================================
# PROCESS WAZUH BYTES
# =========================================================

def process_wazuh_bytes(
    data: bytes,
    log_type: str
):

    decoded_events = []

    if not data:

        print(
            f"[WAZUH] No data received "
            f"for {log_type}"
        )

        return decoded_events

    text = data.decode(
        "utf-8",
        errors="replace"
    )

    total_lines = 0
    valid_json = 0
    decode_errors = 0

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        total_lines += 1

        # -----------------------------------------------------
        # Parse JSON
        # -----------------------------------------------------

        try:

            raw_event = json.loads(
                line
            )

            valid_json += 1

        except json.JSONDecodeError as error:

            decode_errors += 1

            print(
                f"[PIPELINE] Invalid JSON "
                f"in {log_type}: "
                f"{error}"
            )

            continue

        # -----------------------------------------------------
        # Decode Wazuh event
        # -----------------------------------------------------

        try:

            decoded_event = (
                decode_wazuh_event(
                    raw_event,
                    log_type
                )
            )

        except Exception as error:

            print(
                f"[PIPELINE] Decoder error "
                f"in {log_type}: "
                f"{error}"
            )

            continue

        if not decoded_event:

            print(
                f"[PIPELINE] Decoder returned "
                f"empty event for {log_type}"
            )

            continue

        # -----------------------------------------------------
        # Preserve original Wazuh metadata
        # -----------------------------------------------------

        if isinstance(
            decoded_event,
            dict
        ):

            # Preserve Wazuh event ID
            if "id" not in decoded_event:

                decoded_event[
                    "id"
                ] = raw_event.get(
                    "id"
                )

            # Preserve raw Wazuh event
            decoded_event.setdefault(
                "raw_event",
                raw_event
            )

            # Preserve log type
            decoded_event.setdefault(
                "log_type",
                log_type
            )

        decoded_events.append(
            decoded_event
        )

    # =========================================================
    # PIPELINE SUMMARY
    # =========================================================

    print()
    print(
        f"[WAZUH PIPELINE] "
        f"{log_type}"
    )

    print(
        f"  Input lines   : "
        f"{total_lines}"
    )

    print(
        f"  Valid JSON    : "
        f"{valid_json}"
    )

    print(
        f"  Decode errors : "
        f"{decode_errors}"
    )

    print(
        f"  Decoded events: "
        f"{len(decoded_events)}"
    )

    return decoded_events


# =========================================================
# MAP WAZUH EVENTS
# =========================================================

def map_wazuh_events(
    events,
    mapping_path="wazuh_mappingDB_lab.csv"
):

    if not events:

        print(
            "[WAZUH → MITRE] "
            "No events received by mapper."
        )

        return []

    print()
    print(
        "[WAZUH → MITRE] "
        "Initializing mapping engine..."
    )

    print(
        f"[WAZUH → MITRE] "
        f"Database: {mapping_path}"
    )

    # ---------------------------------------------------------
    # Create engine
    # ---------------------------------------------------------

    engine = WazuhMappingEngine(
        mapping_path
    )

    # ---------------------------------------------------------
    # Map all events
    # ---------------------------------------------------------

    results = engine.map_events(
        events
    )

    return results


# =========================================================
# PROCESS + MAP
# =========================================================

def process_and_map_wazuh_bytes(
    data: bytes,
    log_type: str,
    mapping_path="wazuh_mappingDB_lab.csv"
):

    # ---------------------------------------------------------
    # STEP 1
    # Wazuh JSON → decoded normalized events
    # ---------------------------------------------------------

    decoded_events = (
        process_wazuh_bytes(
            data,
            log_type
        )
    )

    if not decoded_events:

        print(
            "[WAZUH PIPELINE] "
            "No decoded events to map."
        )

        return []

    # ---------------------------------------------------------
    # STEP 2
    # decoded events → MITRE ATT&CK
    # ---------------------------------------------------------

    mapped_events = (
        map_wazuh_events(
            decoded_events,
            mapping_path
        )
    )

    return mapped_events