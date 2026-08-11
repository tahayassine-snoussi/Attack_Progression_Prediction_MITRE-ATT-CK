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
              mappings = database[ database["log_type"] == e.log_type ] 
              for mapping in mappings :
                  if mapping["correlation_required"] : 
                      result = correlate_zeek_events(e, mapping["correlation_rule"])