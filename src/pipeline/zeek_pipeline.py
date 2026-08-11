import json

from correlation.engine import correlate_zeek_events
from decoder.decoder_engine import decode_zeek_event


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


def map_zeek_events(events):

    with open( "zeek_mappingDB.json", "r", encoding="utf-8") as f:
        database = json.load(f)
        
        for e in enumerate(events) :
            results  = []
            mappings = database[ database["log_type"] == e.log_type ] 

            correlation_mapping = mappings[ mappings["correlation_required"] == True ]
            semantic_mapping = mappings[ mappings["correlation_required"] == False ]

            for mapping in correlation_mapping :
                # gets the needed logs for correlation and executes the correlation engine
                result = correlate_zeek_events(e, mapping["correlation_rule"])
                results.append(result)

            results = semantically_map_events(e, semantic_mapping)

    return results



def semantically_map_events(event, semantic_mapping) : 
    """
    Maps the event to the normalized format based on the semantic mapping provided.
    And ranked by the score.
    """

    return