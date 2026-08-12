import json

from correlation.engine import correlate_zeek_events
from decoder.decoder_engine import decode_zeek_event
from semantic_zeek_mapping_engine import (ZeekSemanticMappingEngine)

semantic_engine = ZeekSemanticMappingEngine(
    "zeek_mappingDB.json"
)

def process_zeek_bytes(data: bytes, log_type: str):

    decoded_events = []

    text = data.decode("utf-8", errors="replace")

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        try:
            raw_event = json.loads(line)

        except json.JSONDecodeError as error:
            print(f"[PIPELINE] Invalid JSON in {log_type}: {error}")
            continue

        decoded_event = decode_zeek_event(raw_event, log_type)
        decoded_events.append(decoded_event)

    return decoded_events

def load_zeek_mapping_database(path="zeek_mappingDB.json"):
    with open(path, "r", encoding="utf-8") as f:
        database = json.load(f)

    # If your database is directly a list of mappings
    if isinstance(database, list):
        return database

    # If you later wrap it:
    #
    # {
    #     "database_metadata": {...},
    #     "mappings": [...]
    # }
    #
    if isinstance(database, dict):
        return database.get("mappings", [])

    raise ValueError(
        "Invalid Zeek mapping database format"
    )

def map_zeek_events(
    events,
    semantic_engine,
    correlation_engine=None,
    context_provider=None
):

    semantic_results = semantic_engine.map_events(
        events,
        context_provider
    )


    correlation_results = []


    if correlation_engine is not None:

        correlation_results = (
            correlation_engine.correlate(
                events
            )
        )


    return {

        "semantic_results":
            semantic_results,

        "correlation_results":
            correlation_results
    }
