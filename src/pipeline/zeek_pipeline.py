import json

from decoder.decoder_engine import decode_zeek_event

from .semantic_zeek_mapping_engine import (
    ZeekSemanticMappingEngine
)

from correlation.correlationEngine import (
    CorrelationEngine
)

from correlation.correlation_helpers import (
    get_needed_logs
)


# ============================================================
# LOAD SEMANTIC ENGINE ONCE
# ============================================================

semantic_engine = ZeekSemanticMappingEngine(
    "zeek_mappingDB.json"
)


# ============================================================
# LOAD DATABASE
# ============================================================

def load_zeek_mapping_database(
    path="zeek_mappingDB.json"
):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        database = json.load(f)

    if isinstance(database, list):

        return database

    if isinstance(database, dict):

        return database.get(
            "mappings",
            []
        )

    raise ValueError(
        "Invalid Zeek mapping database format"
    )


# ============================================================
# PROCESS ZEek BYTES
# ============================================================

def process_zeek_bytes(
    data: bytes,
    log_type: str
):

    decoded_events = []

    text = data.decode(
        "utf-8",
        errors="replace"
    )

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        try:

            raw_event = json.loads(
                line
            )

        except json.JSONDecodeError as error:

            print(
                f"[PIPELINE] Invalid JSON "
                f"in {log_type}: {error}"
            )

            continue

        decoded_event = decode_zeek_event(
            raw_event,
            log_type
        )

        decoded_events.append(
            decoded_event
        )

    return decoded_events


# ============================================================
# SEMANTIC LOGGING
# ============================================================

def print_semantic_mapping(
    event,
    match
):

    technique_id = match.get(
        "technique_id"
    )

    technique_name = match.get(
        "technique_name"
    )

    tactic = match.get(
        "tactic"
    )

    mapping_id = match.get(
        "mapping_id"
    )

    score = match.get(
        "score",
        0.0
    )

    confidence = match.get(
        "confidence_score",
        0.0
    )

    matched_conditions = (
        match.get(
            "matched_conditions"
        )
        or []
    )

    print()
    print("=" * 80)
    print("[ZEEK → MITRE ATT&CK] SEMANTIC MATCH")
    print("=" * 80)

    print(
        f"Mapping ID : {mapping_id}"
    )

    print(
        f"Log type  : {event.get('log_type')}"
    )

    print(
        f"Timestamp : {event.get('timestamp')}"
    )

    print(
        f"Technique : "
        f"{technique_id} - {technique_name}"
    )

    print(
        f"Tactic    : {tactic}"
    )

    print(
        f"Confidence: {confidence:.4f}"
    )

    print(
        f"Score     : {score:.4f}"
    )

    if matched_conditions:

        print(
            "Matched conditions:"
        )

        for condition in matched_conditions:

            print(
                f"  - {condition}"
            )

    print("=" * 80)


# ============================================================
# CORRELATION LOGGING
# ============================================================

def print_correlation_mapping(
    event,
    mapping,
    correlation_result
):

    technique = mapping.get(
        "attack_technique",
        {}
    )

    technique_id = technique.get(
        "technique_id"
    )

    technique_name = technique.get(
        "technique_name"
    )

    tactic = technique.get(
        "tactic"
    )

    mapping_id = mapping.get(
        "mapping_id"
    )

    confidence = float(
        mapping.get(
            "confidence_score",
            0.0
        )
    )

    correlation_rule = mapping.get(
        "correlation_rule",
        {}
    )

    window_seconds = correlation_rule.get(
        "window_seconds"
    )

    print()
    print("=" * 80)
    print("[ZEEK → MITRE ATT&CK] CORRELATION MATCH")
    print("=" * 80)

    print(
        f"Mapping ID : {mapping_id}"
    )

    print(
        f"Log type  : {mapping.get('log_type')}"
    )

    print(
        f"Trigger   : {event.get('timestamp')}"
    )

    print(
        f"Technique : "
        f"{technique_id} - {technique_name}"
    )

    print(
        f"Tactic    : {tactic}"
    )

    print(
        f"Base conf.: {confidence:.4f}"
    )

    print(
        f"Window    : {window_seconds} seconds"
    )

    for index, result in enumerate(
        correlation_result.get(
            "results",
            []
        ),
        start=1
    ):

        print()
        print(
            f"Correlation result #{index}"
        )

        print(
            f"  Group : "
            f"{result.get('group')}"
        )

        print(
            f"  Score : "
            f"{result.get('score')}"
        )

        metrics = result.get(
            "metrics",
            {}
        )

        if metrics:

            print(
                "  Metrics:"
            )

            for name, value in metrics.items():

                print(
                    f"    {name}: {value}"
                )

        conditions = result.get(
            "conditions",
            {}
        )

        condition_results = conditions.get(
            "results",
            []
        )

        if condition_results:

            print(
                "  Conditions:"
            )

            for condition in condition_results:

                print(
                    f"    {condition.get('metric')} "
                    f"{condition.get('operator')} "
                    f"{condition.get('expected')} "
                    f"→ actual={condition.get('actual')} "
                    f"matched={condition.get('matched')}"
                )

        state = result.get(
            "state_condition"
        )

        if state:

            print(
                "  State condition:"
            )

            print(
                f"    {state}"
            )

    print("=" * 80)


# ============================================================
# MAP ZEEK EVENTS
# ============================================================

def map_zeek_events(
    events,
    semantic_engine,
    correlation_engine=None,
    context_provider=None
):

    # ========================================================
    # 1. SEMANTIC MAPPING
    # ========================================================

    semantic_results = (
        semantic_engine.map_events(
            events,
            context_provider
        )
    )

    # --------------------------------------------------------
    # PRINT ONLY SUCCESSFUL SEMANTIC MATCHES
    # --------------------------------------------------------

    for item in semantic_results:

        event = item.get(
            "event"
        )

        matches = item.get(
            "matches",
            []
        )

        for match in matches:

            print_semantic_mapping(
                event,
                match
            )

    # ========================================================
    # 2. LOAD CORRELATION MAPPINGS
    # ========================================================

    mappings = semantic_engine.mappings

    correlation_results = []

    # ========================================================
    # 3. CORRELATION
    # ========================================================

    for mapping in mappings:

        if not mapping.get(
            "correlation_required",
            False
        ):

            continue

        correlation_rule = mapping.get(
            "correlation_rule"
        )

        if not correlation_rule:

            continue

        target_log_type = mapping.get(
            "log_type"
        )

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

            continue

        # ----------------------------------------------------
        # Only use events belonging to this mapping.
        # ----------------------------------------------------

        candidate_events = [

            event

            for event in events

            if event.get(
                "log_type"
            ) in target_log_types
        ]

        if not candidate_events:

            continue

        # ----------------------------------------------------
        # Every event can be a correlation trigger.
        #
        # get_needed_logs() extracts the events around that
        # trigger using correlation_rule.window_seconds.
        # ----------------------------------------------------

        mapping_detected = False

        for trigger_event in candidate_events:

            needed_events = get_needed_logs(
                trigger_event,
                candidate_events,
                mapping
            )

            if not needed_events:

                continue

            engine = (
                correlation_engine
                if correlation_engine is not None
                else CorrelationEngine()
            )

            result = engine.correlate(
                needed_events,
                correlation_rule
            )

            # ------------------------------------------------
            # NOTHING DETECTED:
            # SILENTLY CONTINUE
            # ------------------------------------------------

            if not result.get(
                "detected",
                False
            ):

                continue

            # ------------------------------------------------
            # CORRELATION DETECTED
            # ------------------------------------------------

            correlation_results.append({

                "mapping_id":
                    mapping.get(
                        "mapping_id"
                    ),

                "event":
                    trigger_event,

                "mapping":
                    mapping,

                "correlation":
                    result
            })

            print_correlation_mapping(
                trigger_event,
                mapping,
                result
            )

            mapping_detected = True

            # ------------------------------------------------
            # We already detected this mapping.
            #
            # Do not print the same correlation repeatedly
            # for every trigger event.
            # ------------------------------------------------

            break

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "semantic_results":
            semantic_results,

        "correlation_results":
            correlation_results
    }