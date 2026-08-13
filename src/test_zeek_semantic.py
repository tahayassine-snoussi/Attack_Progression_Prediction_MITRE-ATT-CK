import json

from decoder.decoder_engine import decode_zeek_event
from pipeline.semantic_zeek_mapping_engine import ZeekSemanticMappingEngine

class TestContextProvider:

    def __init__(self, context):
        self.context = context

    def resolve(self, context_key, event):

        return self.context.get(context_key)

    
DB_PATH = "zeek_mappingDB.json"


def load_database(path):

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    context_provider = TestContextProvider({

        "source_host.location": "internal",

        "source_host.role": "workstation"

    })
    
    print("=" * 70)
    print("ZEEK → MITRE ATT&CK MAPPING TEST")
    print("=" * 70)

    # =========================================================
    # 1. Load database
    # =========================================================

    database = load_database(DB_PATH)

    print(f"[+] Loaded database: {DB_PATH}")

    mappings = database["mappings"]

    # =========================================================
    # 2. Select ONE mapping
    # =========================================================

    target_mapping = next(
        m for m in mappings
        if m["mapping_id"] == "ZEK-T1590.001-001"
    )

    print(
        f"[+] Testing mapping: "
        f"{target_mapping['mapping_id']}"
    )

    technique = target_mapping["attack_technique"]

    print(
        f"[+] Technique: "
        f"{technique['technique_id']} - "
        f"{technique['technique_name']}"
    )

    # =========================================================
    # 3. Raw Zeek event
    # =========================================================

    raw_event = {
        "ts": 1755086400.0,
        "id.orig_h": "192.168.1.50",
        "query": "example.com",
        "qtype": 15,
        "qtype_name": "MX",
        "answers": [
            "mail.example.com"
        ],
        "rcode": 0
    }

    print("\n[+] Raw Zeek event:")

    print(
        json.dumps(
            raw_event,
            indent=4
        )
    )

    # =========================================================
    # 4. Decode Zeek event
    # =========================================================

    decoded_event = decode_zeek_event(
        log_event=raw_event,
        log_type="dns.log"
    )

    print("\n[+] Decoded event:")

    print(
        json.dumps(
            decoded_event,
            indent=4,
            default=str
        )
    )

    # =========================================================
    # 5. Create mapping engine
    # =========================================================

    engine = ZeekSemanticMappingEngine(
        DB_PATH
    )

    print("\n[+] Mapping engine initialized")

    # =========================================================
    # 6. Test ONE mapping directly
    # =========================================================

    result = engine.match_mapping(
        event=decoded_event,
        mapping=target_mapping
    )

    # =========================================================
    # 7. Print result
    # =========================================================

    print("\n" + "=" * 70)
    print("MAPPING RESULT")
    print("=" * 70)

    print(
        json.dumps(
            result.to_dict(),
            indent=4,
            default=str
        )
    )


if __name__ == "__main__":
    main()