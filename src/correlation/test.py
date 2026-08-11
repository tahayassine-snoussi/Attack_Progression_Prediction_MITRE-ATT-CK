import json

from correlationEngine import CorrelationEngine


# ============================================================
# LOAD MAPPING DATABASE
# ============================================================

with open(
    "zeek_mappingDB.json",
    "r",
    encoding="utf-8"
) as f:

    database = json.load(f)


# ============================================================
# GET CORRELATION RULE
# ============================================================

mapping = database["mappings"][0]

correlation_rule = mapping["correlation_rule"]


# ============================================================
# LOAD JSONL EVENTS
# ============================================================

logs = []

with open(
    "data/events/conn.log.jsonl",
    "r",
    encoding="utf-8"
) as f:

    for line_number, line in enumerate(f, start=1):

        line = line.strip()

        if not line:
            continue

        try:

            event = json.loads(line)

            logs.append(event)

        except json.JSONDecodeError as error:

            print(
                f"[ERROR] Invalid JSON on line "
                f"{line_number}: {error}"
            )


# ============================================================
# RUN CORRELATION
# ============================================================

engine = CorrelationEngine()

result = engine.correlate(
    logs,
    correlation_rule
)


# ============================================================
# DISPLAY RESULT
# ============================================================

print(
    json.dumps(
        result,
        indent=4,
        ensure_ascii=False
    )
)