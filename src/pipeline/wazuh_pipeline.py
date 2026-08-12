import csv
import json
from decoder.decoder_engine import decode_wazuh_event
from wazuh_mapping_engine import WazuhMappingEngine



def process_wazuh_bytes(data: bytes, log_type: str):

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

        decoded_event = decode_wazuh_event(raw_event, log_type)
        decoded_events.append(decoded_event)

    return decoded_events


def map_wazuh_events(events):

    engine = WazuhMappingEngine("mapping_dataset.csv")
    return engine.map_events(events)


