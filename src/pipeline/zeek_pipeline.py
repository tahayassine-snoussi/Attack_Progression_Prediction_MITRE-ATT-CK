import json

from decoder.decoder_engine import decode_zeek_event

from .semantic_zeek_mapping_engine import (
    ZeekSemanticMappingEngine
)

from correlation.zeek_correlation import (
    ZeekCorrelationPipeline
)


# ============================================================
# SEMANTIC DATABASE
# ============================================================

def load_zeek_semantic_mapping_database(
    path="zeek_semantic_mappingDB.json"
):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        database = json.load(f)

    if isinstance(
        database,
        list
    ):

        return database

    if isinstance(
        database,
        dict
    ):

        return database.get(
            "mappings",
            []
        )

    raise ValueError(
        "Invalid Zeek semantic mapping database format"
    )


# ============================================================
# CORRELATION DATABASE
# ============================================================

def load_zeek_correlation_mapping_database(
    path="zeek_correlation_mappingDB.json"
):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        database = json.load(f)

    if isinstance(
        database,
        list
    ):

        return database

    if isinstance(
        database,
        dict
    ):

        return database.get(
            "mappings",
            []
        )

    raise ValueError(
        "Invalid Zeek correlation mapping database format"
    )


# ============================================================
# LOAD SEMANTIC ENGINE
# ============================================================

semantic_engine = ZeekSemanticMappingEngine(
    "zeek_semantic_mappingDB.json"
)


# ============================================================
# LOAD CORRELATION MAPPINGS
# ============================================================

correlation_mappings = (
    load_zeek_correlation_mapping_database(
        "zeek_correlation_mappingDB.json"
    )
)


# ============================================================
# LOAD CORRELATION PIPELINE
# ============================================================

correlation_pipeline = (
    ZeekCorrelationPipeline(
        correlation_mappings
    )
)


# ============================================================
# PROCESS ZEEK BYTES
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
# SEMANTIC MAPPING
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
    print(
        "[ZEEK → MITRE ATT&CK] "
        "SEMANTIC MATCH"
    )
    print("=" * 80)

    print(
        f"Mapping ID : {mapping_id}"
    )

    print(
        f"Log type   : "
        f"{event.get('log_type')}"
    )

    print(
        f"Timestamp  : "
        f"{event.get('timestamp')}"
    )

    print(
        f"Technique  : "
        f"{technique_id} - "
        f"{technique_name}"
    )

    print(
        f"Tactic     : "
        f"{tactic}"
    )

    print(
        f"Confidence : "
        f"{confidence:.4f}"
    )

    print(
        f"Score      : "
        f"{score:.4f}"
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

def print_correlation_detection(
    detection
):

    mapping_id = detection.get(
        "mapping_id"
    )

    technique = detection.get(
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

    confidence = float(
        detection.get(
            "confidence_score",
            0.0
        )
    )

    group_key = detection.get(
        "group_key"
    )

    time_group_id = detection.get(
        "time_group_id"
    )

    correlation_result = detection.get(
        "correlation_result",
        {}
    )

    print()
    print("=" * 80)
    print(
        "[ZEEK → MITRE ATT&CK] "
        "CORRELATION DETECTED"
    )
    print("=" * 80)

    print(
        f"Mapping ID : {mapping_id}"
    )

    print(
        f"Technique  : "
        f"{technique_id} - "
        f"{technique_name}"
    )

    print(
        f"Tactic     : "
        f"{tactic}"
    )

    print(
        f"Confidence : "
        f"{confidence:.4f}"
    )

    print(
        f"Time group : "
        f"{time_group_id}"
    )

    print(
        f"Group key  : "
        f"{group_key}"
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
            f"  Score: "
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

        for condition in conditions.get(
            "results",
            []
        ):

            print(
                f"  {condition.get('metric')} "
                f"{condition.get('operator')} "
                f"{condition.get('expected')} "
                f"→ actual="
                f"{condition.get('actual')} "
                f"matched="
                f"{condition.get('matched')}"
            )

    print("=" * 80)


# ============================================================
# MAP ZEEK EVENTS SEMANTICALLY
# ============================================================

def map_zeek_events(
    events,
    semantic_engine,
    context_provider=None
):

    semantic_results = (
        semantic_engine.map_events(
            events,
            context_provider
        )
    )

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

    return {
        "semantic_results":
            semantic_results
    }


# ============================================================
# CORRELATION
# ============================================================

def detect_correlation(
    events
):

    detections = (
        correlation_pipeline.process(
            events
        )
    )

    for detection in detections:

        print_correlation_detection(
            detection
        )

    return detections