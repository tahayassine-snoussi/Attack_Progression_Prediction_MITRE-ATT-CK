import csv
from collections import defaultdict


class WazuhMappingEngine:

    def __init__(self, mapping_path):
        self.mapping_path = mapping_path
        self.mappings = []
        self.index = defaultdict(list)

        self.load_database()
        self.build_indexes()

    # ---------------------------------------------------------
    # DATABASE
    # ---------------------------------------------------------

    def load_database(self):
        with open(self.mapping_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                self.mappings.append(row)

    # ---------------------------------------------------------
    # INDEX
    # ---------------------------------------------------------

    def build_indexes(self):

        for mapping in self.mappings:

            event_id = self.clean(mapping.get("event_id"))

            if event_id:
                self.index[("event_id", event_id)].append(mapping)

            provider = self.clean(mapping.get("provider"))

            if provider:
                self.index[("provider", provider)].append(mapping)

    # ---------------------------------------------------------
    # NORMALIZATION
    # ---------------------------------------------------------

    @staticmethod
    def clean(value):

        if value is None:
            return None

        value = str(value).strip()

        if not value:
            return None

        return value.lower()

    # ---------------------------------------------------------
    # EVENT IDENTITY
    # ---------------------------------------------------------

    def extract_event_identity(self, event):

        fields = event.get("decoded_fields", {})

        return {
            "event_id": self.clean(
                fields.get("event.id")
                or fields.get("winlog.event_id")
                or fields.get("data.id")
            ),

            "provider": self.clean(
                fields.get("event.provider")
                or fields.get("winlog.provider_name")
            ),

            "channel": self.clean(
                fields.get("event.channel")
                or fields.get("winlog.channel")
            ),

            "platform": self.clean(
                fields.get("platform")
            ),

            "event_type": self.clean(
                fields.get("event.type")
            ),

            "action": self.clean(
                fields.get("event.action")
            )
        }

    # ---------------------------------------------------------
    # CANDIDATES
    # ---------------------------------------------------------

    def get_candidate_mappings(self, identity):

        candidates = {}

        event_id = identity.get("event_id")

        if event_id:

            for mapping in self.index.get(("event_id", event_id), []):

                mapping_id = mapping.get("mapping_id")
                candidates[mapping_id] = mapping

        provider = identity.get("provider")

        if provider:

            for mapping in self.index.get(("provider", provider), []):

                mapping_id = mapping.get("mapping_id")
                candidates[mapping_id] = mapping

        return list(candidates.values())

    # ---------------------------------------------------------
    # MATCH
    # ---------------------------------------------------------

    def match_mapping(self, event, mapping, identity):

        matched_fields = {}
        total = 0
        matched = 0

        # Event ID
        mapping_event_id = self.clean(mapping.get("event_id"))

        if mapping_event_id:

            total += 1

            result = (identity.get("event_id")== mapping_event_id)

            matched_fields["event_id"] = result

            if result:
                matched += 1

        # Provider
        mapping_provider = self.clean(mapping.get("provider"))

        if mapping_provider:

            total += 1

            result = (identity.get("provider") == mapping_provider)

            matched_fields["provider"] = result

            if result:
                matched += 1

        # Channel
        mapping_channel = self.clean(mapping.get("channel"))

        if mapping_channel:
            total += 1

            result = (identity.get("channel") == mapping_channel)

            matched_fields["channel"] = result

            if result:
                matched += 1

        # Platform
        mapping_platform = self.clean(mapping.get("platform"))

        if mapping_platform:

            total += 1
            result = (identity.get("platform") == mapping_platform)

            matched_fields["platform"] = result

            if result:
                matched += 1

        if total == 0:

            return {
                "matched": False,
                "score": 0.0,
                "matched_fields": {}
            }

        score = matched / total

        return {
            "matched": matched == total,
            "score": score,
            "matched_fields": matched_fields
        }

    # ---------------------------------------------------------
    # MAP ONE EVENT
    # ---------------------------------------------------------

    def map_event(self, event):

        identity = self.extract_event_identity(event)

        candidates = self.get_candidate_mappings(identity)

        results = []

        for mapping in candidates:

            match = self.match_mapping(event, mapping, identity)

            if not match["matched"]:
                continue

            confidence = self.to_float(
                mapping.get(
                    "confidence_score"
                )
            )

            final_score = (
                match["score"]
                * confidence
            )

            results.append({

                "mapping_id":
                    mapping.get("mapping_id"),

                "technique": {
                    "id":
                        mapping.get(
                            "technique_id"
                        ),

                    "name":
                        mapping.get(
                            "technique_name"
                        ),

                    "tactic":
                        mapping.get(
                            "tactic"
                        )
                },

                "match": {
                    "matched": True,

                    "score":
                        round(
                            final_score,
                            4
                        ),

                    "confidence_score":
                        confidence,

                    "matched_fields":
                        match[
                            "matched_fields"
                        ]
                },

                "evidence": identity
            })

        results.sort(
            key=lambda x:
                x["match"]["score"],
            reverse=True
        )

        return results

    # ---------------------------------------------------------
    # MAP MANY EVENTS
    # ---------------------------------------------------------

    def map_events(self, events):

        results = []

        for event in events:

            mappings = self.map_event(
                event
            )

            if mappings:

                results.append({

                    "event": event,

                    "mappings": mappings
                })

        return results

    # ---------------------------------------------------------
    # HELPERS
    # ---------------------------------------------------------

    @staticmethod
    def to_float(value):

        try:
            return float(value)

        except (
            TypeError,
            ValueError
        ):
            return 0.0