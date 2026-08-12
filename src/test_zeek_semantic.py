import json

from pipeline.semantic_zeek_mapping_engine import (
    ZeekSemanticMappingEngine
)


# ============================================================
# CONFIGURATION
# ============================================================

MAPPING_DB = "zeek_mappingDB.json"


# ============================================================
# TEST EVENTS
# ============================================================

events = [

    {
        "telemetry_source": "Zeek",
        "log_type": "ssh.log",
        "timestamp": "2026-08-09T18:07:07.845+00:00",
        "decoded_fields": {
            "ssh.auth_success": True,
            "ssh.client": "SSH-2.0-paramiko_5.0.0",
            "ssh.direction": None,
            "ssh.id.orig_h": "192.168.56.1",
            "ssh.id.resp_h": "192.168.56.10",
            "ssh.server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15",
            "ssh.ts": "2026-08-09T18:07:07.845+00:00"
        }
    },

    {
        "telemetry_source": "Zeek",
        "log_type": "ssh.log",
        "timestamp": "2026-08-09T18:19:14.905+00:00",
        "decoded_fields": {
            "ssh.auth_success": True,
            "ssh.client": "SSH-2.0-paramiko_5.0.0",
            "ssh.direction": None,
            "ssh.id.orig_h": "192.168.56.1",
            "ssh.id.resp_h": "192.168.56.10",
            "ssh.server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15",
            "ssh.ts": "2026-08-09T18:19:14.905+00:00"
        }
    },

    {
        "telemetry_source": "Zeek",
        "log_type": "ssh.log",
        "timestamp": "2026-08-09T18:28:24.563+00:00",
        "decoded_fields": {
            "ssh.auth_success": True,
            "ssh.client": "SSH-2.0-paramiko_5.0.0",
            "ssh.direction": None,
            "ssh.id.orig_h": "192.168.56.1",
            "ssh.id.resp_h": "192.168.56.10",
            "ssh.server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15",
            "ssh.ts": "2026-08-09T18:28:24.563+00:00"
        }
    },

    {
        "telemetry_source": "Zeek",
        "log_type": "ssh.log",
        "timestamp": "2026-08-09T18:53:08.196+00:00",
        "decoded_fields": {
            "ssh.auth_success": True,
            "ssh.client": "SSH-2.0-paramiko_5.0.0",
            "ssh.direction": None,
            "ssh.id.orig_h": "192.168.56.1",
            "ssh.id.resp_h": "192.168.56.10",
            "ssh.server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15",
            "ssh.ts": "2026-08-09T18:53:08.196+00:00"
        }
    },

    {
        "telemetry_source": "Zeek",
        "log_type": "ssh.log",
        "timestamp": "2026-08-11T17:44:43.556+00:00",
        "decoded_fields": {
            "ssh.auth_success": True,
            "ssh.client": "SSH-2.0-paramiko_5.0.0",
            "ssh.direction": None,
            "ssh.id.orig_h": "192.168.56.1",
            "ssh.id.resp_h": "192.168.56.10",
            "ssh.server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15",
            "ssh.ts": "2026-08-11T17:44:43.556+00:00"
        }
    }
]


# ============================================================
# CREATE ENGINE
# ============================================================

engine = ZeekSemanticMappingEngine(
    MAPPING_DB
)


# ============================================================
# RUN SEMANTIC MAPPING
# ============================================================

results = engine.map_events(
    events
)


# ============================================================
# PRINT RESULTS
# ============================================================

print("\n")
print("=" * 80)
print("ZEek SEMANTIC MAPPING TEST")
print("=" * 80)


for index, result in enumerate(results, start=1):

    event = result["event"]
    matches = result["matches"]

    print("\n")
    print("-" * 80)
    print(f"EVENT #{index}")
    print("-" * 80)

    print(
        f"Log type : {event.get('log_type')}"
    )

    print(
        f"Timestamp: {event.get('timestamp')}"
    )


    if not matches:

        print("\nNo semantic mapping matched.")

        continue


    print(
        f"\nMatched mappings: {len(matches)}"
    )


    for match_index, match in enumerate(
        matches,
        start=1
    ):

        print(
            f"\n  Match #{match_index}"
        )

        print(
            f"  Mapping ID : "
            f"{match.get('mapping_id')}"
        )

        print(
            f"  Technique  : "
            f"{match.get('technique_id')}"
        )

        print(
            f"  Name       : "
            f"{match.get('technique_name')}"
        )

        print(
            f"  Tactic     : "
            f"{match.get('tactic')}"
        )

        print(
            f"  Confidence : "
            f"{match.get('confidence_score')}"
        )

        print(
            f"  Score      : "
            f"{match.get('score')}"
        )

        print(
            f"  Reason     : "
            f"{match.get('reason')}"
        )


# ============================================================
# OPTIONAL: SAVE RESULTS
# ============================================================

with open(
    "semantic_test_results.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        results,
        f,
        indent=4,
        ensure_ascii=False
    )


print("\n")
print("=" * 80)
print("Results saved to semantic_test_results.json")
print("=" * 80)