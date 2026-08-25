import json
from pathlib import Path


# ============================================================
# PATH TO ZEEK SCHEMAS
# ============================================================

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas" / "zeek"

# Deduplicate schema loading prints
_printed_schemas = set()


# ============================================================
# LOAD SCHEMA
# ============================================================

def load_schema(log_type: str) -> dict:
    """
    Load the schema corresponding to a Zeek log type.

    Example:
        conn.log -> schemas/zeek/conn.json
        dns.log  -> schemas/zeek/dns.json
    """

    log_type = log_type.strip()

    if log_type.endswith(".log"):
        schema_name = log_type[:-4] + ".json"
    else:
        schema_name = log_type + ".json"

    schema_path = SCHEMA_DIR / schema_name

    if not schema_path.exists():
        raise FileNotFoundError(
            f"No schema found for Zeek log type: {log_type}\n"
            f"Expected schema path: {schema_path}"
        )

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Only print the first time a schema is loaded
    if schema_path not in _printed_schemas:
        _printed_schemas.add(schema_path)
        print(f"[DECODER] Loaded schema: {schema_path}")

    return schema


from datetime import datetime, timezone


def normalize_timestamp(timestamp):

    if timestamp is None:
        return None

    return datetime.fromtimestamp(
        float(timestamp),
        tz=timezone.utc
    ).isoformat(timespec="milliseconds")

# ============================================================
# EXTRACT REQUIRED VALUES
# ============================================================

def extract_values(log_event: dict, schema: dict) -> dict:

    required_fields = schema.get("fields", [])

    decoded_values = {}

    log_type = schema["log_type"]

    # Remove .log
    prefix = (
        log_type[:-4]
        if log_type.endswith(".log")
        else log_type
    )

    for normalized_field in required_fields:

        # Example:
        # ftp.ts
        #   ↓
        # ts

        if normalized_field.startswith(prefix + "."):
            raw_field = normalized_field[
                len(prefix) + 1:
            ]
        else:
            raw_field = normalized_field

        value = log_event.get(raw_field)

        # ------------------------------------------------
        # Normalize Zeek timestamp fields
        # ------------------------------------------------
        if normalized_field.endswith(".ts"):
            value = normalize_timestamp(value)

        decoded_values[normalized_field] = value

    return decoded_values

# ============================================================
# MAIN ZEEK DECODER
# ============================================================


def decode_zeek_event(log_event: dict, log_type: str) -> dict:

    """
    Main entry point of the Zeek decoder engine.
    """

    # --------------------------------------------------------
    # 1. Load corresponding schema
    # --------------------------------------------------------

    schema = load_schema(log_type)

    # --------------------------------------------------------
    # 2. Extract required fields
    # --------------------------------------------------------

    decoded_values = extract_values(
        log_event,
        schema
    )

    # --------------------------------------------------------
    # 3. Return normalized decoded event
    # --------------------------------------------------------

    return {
        "telemetry_source": "Zeek",
        "log_type": log_type,
        "timestamp": normalize_timestamp(log_event.get("ts")),
        "decoded_fields": decoded_values
    }




def decode_wazuh_event(log_event: dict, log_type: str) -> dict:

    """
    Main entry point of the Wazuh decoder engine.
    """

    # --------------------------------------------------------
    # 1. Return normalized decoded event
    # --------------------------------------------------------

    return {
        "telemetry_source": "Wazuh",
        "log_type": log_type,
        "timestamp": log_event.get("timestamp"),
        "decoded_fields": log_event
    }