import csv
from collections import defaultdict, Counter


class WazuhMappingEngine:

    def __init__(self, mapping_path):

        self.mapping_path = mapping_path

        self.mappings = []

        # Indexes used to quickly find candidate mappings
        self.index = defaultdict(list)

        self.load_database()
        self.build_indexes()

        print(
            f"[WAZUH MAPPER] Loaded "
            f"{len(self.mappings)} mapping rows"
        )

        print(
            f"[WAZUH MAPPER] Indexes: "
            f"{len(self.index)} keys"
        )

    # =========================================================
    # DATABASE
    # =========================================================

    def load_database(self):

        try:

            with open(
                self.mapping_path,
                "r",
                encoding="utf-8-sig",
                newline=""
            ) as f:

                reader = csv.DictReader(f)

                if reader.fieldnames is None:
                    raise ValueError(
                        "Mapping database has no CSV header"
                    )

                print(
                    "[WAZUH MAPPER] CSV columns:"
                )

                print(
                    ", ".join(reader.fieldnames)
                )

                for row in reader:

                    # Normalize column names
                    normalized = {}

                    for key, value in row.items():

                        if key is None:
                            continue

                        normalized[
                            key.strip()
                        ] = (
                            value.strip()
                            if isinstance(value, str)
                            else value
                        )

                    self.mappings.append(
                        normalized
                    )

        except FileNotFoundError:

            print(
                f"[WAZUH MAPPER] ERROR: "
                f"Mapping database not found: "
                f"{self.mapping_path}"
            )

            raise

        except Exception as error:

            print(
                f"[WAZUH MAPPER] ERROR loading database: "
                f"{error}"
            )

            raise

    # =========================================================
    # INDEX
    # =========================================================

    def build_indexes(self):

        for mapping in self.mappings:

            mapping_id = (
                mapping.get("mapping_id")
                or mapping.get("technique_id")
                or id(mapping)
            )

            # -------------------------------------------------
            # Event ID
            # -------------------------------------------------

            event_id = self.clean(
                mapping.get("event_id")
            )

            if event_id:

                self.index[
                    ("event_id", event_id)
                ].append(mapping)

            # -------------------------------------------------
            # Provider
            # -------------------------------------------------

            provider = self.clean(
                mapping.get("provider")
            )

            if provider:

                self.index[
                    ("provider", provider)
                ].append(mapping)

            # -------------------------------------------------
            # Platform
            # -------------------------------------------------

            platform = self.clean(
                mapping.get("platform")
            )

            if platform:

                self.index[
                    ("platform", platform)
                ].append(mapping)

            # -------------------------------------------------
            # Event type
            # -------------------------------------------------

            event_type = self.clean(
                mapping.get("event_type")
                or mapping.get("event.type")
            )

            if event_type:

                self.index[
                    ("event_type", event_type)
                ].append(mapping)

            # -------------------------------------------------
            # Action
            # -------------------------------------------------

            action = self.clean(
                mapping.get("action")
            )

            if action:

                self.index[
                    ("action", action)
                ].append(mapping)

            # -------------------------------------------------
            # Audit type
            # -------------------------------------------------

            audit_type = self.clean(
                mapping.get("audit_type")
            )

            if audit_type:

                self.index[
                    ("audit_type", audit_type)
                ].append(mapping)

            # -------------------------------------------------
            # Syscall
            # -------------------------------------------------

            syscall = self.clean(
                mapping.get("syscall")
            )

            if syscall:

                self.index[
                    ("syscall", syscall)
                ].append(mapping)

            # -------------------------------------------------
            # Command
            # -------------------------------------------------

            command = self.clean(
                mapping.get("command")
            )

            if command:

                self.index[
                    ("command", command)
                ].append(mapping)

            # -------------------------------------------------
            # Executable
            # -------------------------------------------------

            exe = self.clean(
                mapping.get("exe")
            )

            if exe:

                self.index[
                    ("exe", exe)
                ].append(mapping)

            # -------------------------------------------------
            # Key
            # -------------------------------------------------

            key = self.clean(
                mapping.get("key")
            )

            if key:

                self.index[
                    ("key", key)
                ].append(mapping)

    # =========================================================
    # NORMALIZATION
    # =========================================================

    @staticmethod
    def clean(value):

        if value is None:
            return None

        value = str(value).strip()

        if not value:
            return None

        return value.lower()

    # =========================================================
    # GET NESTED VALUE
    # =========================================================

    @staticmethod
    def get_nested(data, *keys):

        current = data

        for key in keys:

            if not isinstance(current, dict):
                return None

            current = current.get(key)

        return current

    # =========================================================
    # EVENT IDENTITY
    # =========================================================

    def extract_event_identity(self, event):

        decoded_fields = event.get(
            "decoded_fields",
            {}
        )

        data = event.get(
            "data",
            {}
        )

        audit = {}

        # -----------------------------------------------------
        # Wazuh normalized audit object
        # -----------------------------------------------------

        if isinstance(data, dict):

            audit = data.get(
                "audit",
                {}
            )

            if not isinstance(audit, dict):
                audit = {}

        # -----------------------------------------------------
        # Event ID
        # -----------------------------------------------------

        event_id = (
            decoded_fields.get("event.id")
            or decoded_fields.get("winlog.event_id")
            or decoded_fields.get("data.id")
            or audit.get("id")
        )

        # -----------------------------------------------------
        # Provider
        # -----------------------------------------------------

        provider = (
            decoded_fields.get("event.provider")
            or decoded_fields.get(
                "winlog.provider_name"
            )
            or decoded_fields.get("provider")
            or event.get("decoder")
        )

        # decoder can be dict
        if isinstance(provider, dict):

            provider = (
                provider.get("name")
                or provider.get("parent")
            )

        # -----------------------------------------------------
        # Channel
        # -----------------------------------------------------

        channel = (
            decoded_fields.get("event.channel")
            or decoded_fields.get(
                "winlog.channel"
            )
            or decoded_fields.get("channel")
        )

        # -----------------------------------------------------
        # Platform
        # -----------------------------------------------------

        platform = (
            decoded_fields.get("platform")
            or decoded_fields.get("os")
            or decoded_fields.get("host.os")
        )

        # -----------------------------------------------------
        # Event type
        # -----------------------------------------------------

        event_type = (
            decoded_fields.get("event.type")
            or decoded_fields.get("type")
            or audit.get("type")
        )

        # -----------------------------------------------------
        # Action
        # -----------------------------------------------------

        action = (
            decoded_fields.get("event.action")
            or decoded_fields.get("action")
            or audit.get("command")
        )

        # -----------------------------------------------------
        # Audit type
        # -----------------------------------------------------

        audit_type = (
            decoded_fields.get("audit.type")
            or decoded_fields.get("audit_type")
            or audit.get("type")
        )

        # -----------------------------------------------------
        # Syscall
        # -----------------------------------------------------

        syscall = (
            decoded_fields.get("audit.syscall")
            or decoded_fields.get("syscall")
            or audit.get("syscall")
        )

        # -----------------------------------------------------
        # Command
        # -----------------------------------------------------

        command = (
            decoded_fields.get("audit.command")
            or decoded_fields.get("command")
            or audit.get("command")
        )

        # -----------------------------------------------------
        # Executable
        # -----------------------------------------------------

        exe = (
            decoded_fields.get("audit.exe")
            or decoded_fields.get("exe")
            or audit.get("exe")
        )

        # -----------------------------------------------------
        # Key
        # -----------------------------------------------------

        key = (
            decoded_fields.get("audit.key")
            or decoded_fields.get("key")
            or audit.get("key")
        )

        # -----------------------------------------------------
        # CWD
        # -----------------------------------------------------

        cwd = (
            decoded_fields.get("audit.cwd")
            or decoded_fields.get("cwd")
            or audit.get("cwd")
        )

        # -----------------------------------------------------
        # Architecture
        # -----------------------------------------------------

        arch = (
            decoded_fields.get("audit.arch")
            or decoded_fields.get("arch")
            or audit.get("arch")
        )

        # -----------------------------------------------------
        # Build identity
        # -----------------------------------------------------

        identity = {

            "event_id":
                self.clean(event_id),

            "provider":
                self.clean(provider),

            "channel":
                self.clean(channel),

            "platform":
                self.clean(platform),

            "event_type":
                self.clean(event_type),

            "action":
                self.clean(action),

            "audit_type":
                self.clean(audit_type),

            "syscall":
                self.clean(syscall),

            "command":
                self.clean(command),

            "exe":
                self.clean(exe),

            "key":
                self.clean(key),

            "cwd":
                self.clean(cwd),

            "arch":
                self.clean(arch)
        }

        # -----------------------------------------------------
        # Automatically recognize Linux auditd
        # -----------------------------------------------------

        if (
            identity["audit_type"]
            or identity["syscall"]
            or identity["exe"]
        ):

            if not identity["platform"]:
                identity["platform"] = "linux"

            if not identity["provider"]:
                identity["provider"] = "auditd"

        return identity

    # =========================================================
    # CANDIDATES
    # =========================================================

    def get_candidate_mappings(
        self,
        identity
    ):

        candidates = {}

        lookup_fields = [
            "event_id",
            "provider",
            "platform",
            "event_type",
            "action",
            "audit_type",
            "syscall",
            "command",
            "exe",
            "key"
        ]

        for field in lookup_fields:

            value = identity.get(field)

            if not value:
                continue

            for mapping in self.index.get(
                (field, value),
                []
            ):

                mapping_id = (
                    mapping.get("mapping_id")
                    or mapping.get("technique_id")
                    or id(mapping)
                )

                candidates[
                    mapping_id
                ] = mapping

        # -----------------------------------------------------
        # If indexes find nothing, evaluate all mappings.
        #
        # This is slower, but prevents a valid Linux mapping
        # from being silently ignored just because the mapping
        # has no indexed event_id/provider.
        # -----------------------------------------------------

        if not candidates:

            return self.mappings

        return list(
            candidates.values()
        )

    # =========================================================
    # VALUE MATCHING
    # =========================================================

    def values_match(
        self,
        event_value,
        mapping_value
    ):

        event_value = self.clean(
            event_value
        )

        mapping_value = self.clean(
            mapping_value
        )

        if not event_value:
            return False

        if not mapping_value:
            return False

        # Exact
        if event_value == mapping_value:
            return True

        # Mapping can contain multiple alternatives
        alternatives = [
            self.clean(x)
            for x in mapping_value.split("|")
        ]

        if event_value in alternatives:
            return True

        # Mapping can contain comma-separated values
        alternatives = [
            self.clean(x)
            for x in mapping_value.split(",")
        ]

        if event_value in alternatives:
            return True

        # Path matching
        if (
            event_value.startswith("/")
            and mapping_value.startswith("/")
        ):

            if (
                event_value == mapping_value
                or event_value.endswith(
                    mapping_value
                )
            ):
                return True

        return False

    # =========================================================
    # MATCH ONE MAPPING
    # =========================================================

    def match_mapping(
        self,
        event,
        mapping,
        identity
    ):

        matched_fields = {}
        required_fields = 0
        matched = 0

        # -----------------------------------------------------
        # Mapping field → identity field
        # -----------------------------------------------------

        comparisons = [

            (
                "event_id",
                identity.get("event_id"),
                mapping.get("event_id")
            ),

            (
                "provider",
                identity.get("provider"),
                mapping.get("provider")
            ),

            (
                "channel",
                identity.get("channel"),
                mapping.get("channel")
            ),

            (
                "platform",
                identity.get("platform"),
                mapping.get("platform")
            ),

            (
                "event_type",
                identity.get("event_type"),
                (
                    mapping.get("event_type")
                    or mapping.get("event.type")
                )
            ),

            (
                "action",
                identity.get("action"),
                mapping.get("action")
            ),

            (
                "audit_type",
                identity.get("audit_type"),
                mapping.get("audit_type")
            ),

            (
                "syscall",
                identity.get("syscall"),
                mapping.get("syscall")
            ),

            (
                "command",
                identity.get("command"),
                mapping.get("command")
            ),

            (
                "exe",
                identity.get("exe"),
                mapping.get("exe")
            ),

            (
                "key",
                identity.get("key"),
                mapping.get("key")
            )
        ]

        # -----------------------------------------------------
        # Evaluate populated mapping fields
        # -----------------------------------------------------

        for (
            field,
            event_value,
            mapping_value
        ) in comparisons:

            mapping_value = self.clean(
                mapping_value
            )

            if not mapping_value:
                continue

            required_fields += 1

            result = self.values_match(
                event_value,
                mapping_value
            )

            matched_fields[
                field
            ] = result

            if result:
                matched += 1

        # -----------------------------------------------------
        # No usable mapping criteria
        # -----------------------------------------------------

        if required_fields == 0:

            return {
                "matched": False,
                "score": 0.0,
                "matched_fields": {}
            }

        # -----------------------------------------------------
        # IMPORTANT:
        #
        # Require at least one matching field.
        #
        # Do NOT require every DB field to match.
        # This is essential for mixed Windows/Linux
        # telemetry.
        # -----------------------------------------------------

        if matched == 0:

            return {
                "matched": False,
                "score": 0.0,
                "matched_fields":
                    matched_fields
            }

        # -----------------------------------------------------
        # Raw evidence score
        # -----------------------------------------------------

        score = (
            matched /
            required_fields
        )

        # -----------------------------------------------------
        # Strong Linux auditd signals
        # -----------------------------------------------------

        if (
            identity.get("command") == "whoami"
            and (
                self.clean(
                    mapping.get("technique_id")
                )
                == "t1033"
            )
        ):

            score = max(
                score,
                0.90
            )

        return {
            "matched": True,

            "score":
                round(score, 4),

            "matched_fields":
                matched_fields
        }

    # =========================================================
    # MAP ONE EVENT
    # =========================================================

    def map_event(self, event):

        identity = (
            self.extract_event_identity(
                event
            )
        )

        candidates = (
            self.get_candidate_mappings(
                identity
            )
        )

        results = []

        for mapping in candidates:

            match = self.match_mapping(
                event,
                mapping,
                identity
            )

            if not match["matched"]:
                continue

            confidence = self.to_float(
                mapping.get(
                    "confidence_score"
                )
            )

            # -------------------------------------------------
            # If DB has no confidence score, use evidence score
            # -------------------------------------------------

            if confidence <= 0:

                confidence = 1.0

            final_score = (
                match["score"]
                * confidence
            )

            technique_id = (
                mapping.get(
                    "technique_id"
                )
                or mapping.get("technique")
            )

            technique_name = (
                mapping.get(
                    "technique_name"
                )
                or mapping.get("name")
            )

            tactic = (
                mapping.get("tactic")
                or mapping.get("tactics")
            )

            results.append({

                "mapping_id":
                    mapping.get(
                        "mapping_id"
                    ),

                "technique": {

                    "id":
                        technique_id,

                    "name":
                        technique_name,

                    "tactic":
                        tactic
                },

                "match": {

                    "matched":
                        True,

                    "score":
                        round(
                            final_score,
                            4
                        ),

                    "evidence_score":
                        match["score"],

                    "confidence_score":
                        confidence,

                    "matched_fields":
                        match[
                            "matched_fields"
                        ]
                },

                "evidence":
                    identity
            })

        # -----------------------------------------------------
        # Sort highest score first
        # -----------------------------------------------------

        results.sort(
            key=lambda x:
                x["match"]["score"],
            reverse=True
        )

        return results

    # =========================================================
    # PRINT EVENT IDENTITY
    # =========================================================

    def print_event_identity(
        self,
        event,
        identity
    ):

        event_uid = (
            event.get("id")
            or event.get("event_id")
            or "N/A"
        )

        print()
        print(
            "[WAZUH MAPPER] Processing event"
        )

        print(
            f"  Wazuh ID : {event_uid}"
        )

        print(
            f"  Event ID : "
            f"{identity.get('event_id')}"
        )

        print(
            f"  Provider : "
            f"{identity.get('provider')}"
        )

        print(
            f"  Platform : "
            f"{identity.get('platform')}"
        )

        print(
            f"  Type     : "
            f"{identity.get('event_type')}"
        )

        print(
            f"  Command  : "
            f"{identity.get('command')}"
        )

        print(
            f"  EXE      : "
            f"{identity.get('exe')}"
        )

        print(
            f"  Syscall  : "
            f"{identity.get('syscall')}"
        )

        print(
            f"  Key      : "
            f"{identity.get('key')}"
        )

    # =========================================================
    # PRINT MAPPING
    # =========================================================

    def print_mapping(
        self,
        event,
        mapping
    ):

        event_uid = (
            event.get("id")
            or event.get("event_id")
            or "N/A"
        )

        technique = mapping[
            "technique"
        ]

        match = mapping[
            "match"
        ]

        matched_fields = [
            field
            for field, value
            in match[
                "matched_fields"
            ].items()
            if value
        ]

        print(
            f"[WAZUH → MITRE] "
            f"{event_uid} | "
            f"{technique.get('id')} "
            f"{technique.get('name')} | "
            f"score="
            f"{match['score']:.4f} | "
            f"matched="
            f"{', '.join(matched_fields)}"
        )

    # =========================================================
    # MAP MANY EVENTS
    # =========================================================

    def map_events(self, events):

        results = []
        mapped_summary = []

        for event in events:

            # -------------------------------------------------
            # MAP CURRENT EVENT
            # -------------------------------------------------

            mappings = self.map_event(event)

            # -------------------------------------------------
            # NO MAPPING
            #
            # Do absolutely nothing for this event.
            # No print, no summary entry, just continue.
            # -------------------------------------------------

            if not mappings:
                continue

            # -------------------------------------------------
            # EVENT HAS AT LEAST ONE VALID MAPPING
            # -------------------------------------------------

            results.append({
                "event": event,
                "mappings": mappings
            })

            decoded_fields = event.get(
                "decoded_fields",
                {}
            )

            event_id = (
                decoded_fields.get("event.id")
                or decoded_fields.get("winlog.event_id")
                or decoded_fields.get("data.id")
                or "N/A"
            )

            provider = (
                decoded_fields.get("event.provider")
                or decoded_fields.get("winlog.provider_name")
                or "N/A"
            )

            # -------------------------------------------------
            # PRINT ONLY SUCCESSFUL MAPPINGS
            # -------------------------------------------------

            print()
            print("=" * 80)
            print("[WAZUH → MITRE ATT&CK] EVENT MAPPED")
            print("=" * 80)

            print(f"Event ID : {event_id}")
            print(f"Provider : {provider}")

            for mapping in mappings:

                technique = mapping["technique"]
                match = mapping["match"]

                matched_fields = [
                    field
                    for field, matched
                    in match["matched_fields"].items()
                    if matched
                ]

                print(
                    f"Technique : "
                    f"{technique['id']} - {technique['name']}"
                )

                print(
                    f"Tactic    : "
                    f"{technique['tactic']}"
                )

                print(
                    f"Score     : "
                    f"{match['score']:.4f}"
                )

                print(
                    f"Confidence: "
                    f"{match['confidence_score']:.4f}"
                )

                print(
                    f"Matched   : "
                    f"{', '.join(matched_fields)}"
                )

                # -------------------------------------------------
                # SAVE FOR FINAL SUMMARY
                # -------------------------------------------------

                mapped_summary.append({
                    "event_id": event_id,
                    "technique_id": technique["id"],
                    "technique_name": technique["name"],
                    "tactic": technique["tactic"],
                    "score": match["score"],
                    "confidence": match["confidence_score"],
                    "matched_fields": matched_fields
                })

            print("=" * 80)

        # =========================================================
        # FINAL SUMMARY
        # =========================================================

        if not mapped_summary:
            return results

        print()
        print("#" * 80)
        print("[WAZUH → MITRE ATT&CK] MAPPING SUMMARY")
        print("#" * 80)

        print(
            f"Total mapped events     : {len(results)}"
        )

        print(
            f"Total technique mappings: "
            f"{len(mapped_summary)}"
        )

        print()

        for index, item in enumerate(
            mapped_summary,
            start=1
        ):

            print(
                f"{index}. "
                f"Event {item['event_id']} → "
                f"{item['technique_id']} "
                f"{item['technique_name']} | "
                f"Tactic={item['tactic']} | "
                f"Score={item['score']:.4f} | "
                f"Confidence={item['confidence']:.4f} | "
                f"Matched={', '.join(item['matched_fields'])}"
            )

        print("#" * 80)

        return results


    # =========================================================
    # HELPERS
    # =========================================================

    @staticmethod
    def to_float(value):

        try:

            return float(
                value
            )

        except (
            TypeError,
            ValueError
        ):

            return 0.0