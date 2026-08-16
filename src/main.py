from logs_extraction.collector import Collector

from pipeline.zeek_pipeline import (
    process_zeek_bytes,
    map_zeek_events,
    semantic_engine,
    correlation_mappings,
    detect_correlation
)

from pipeline.wazuh_pipeline import (
    process_wazuh_bytes,
    map_wazuh_events
)

from storage.event_store import EventStore


def main():

    collector = Collector()
    event_store = EventStore()

    # ============================================================
    # ACCUMULATORS FOR CROSS-SOURCE DEDUPLICATION
    # ============================================================

    all_wazuh_events = []

    try:

        for source in collector.registry.get_sources():

            try:

                # =====================================================
                # 1. GET NEW BYTES
                # =====================================================

                result = collector.collect_source(source)

                if result is None:
                    continue

                # =====================================================
                # 2. EXTRACT RESULT INFORMATION
                # =====================================================

                data = result["data"]
                log_type = result["log_type"]

                # =====================================================
                # 3. ZEEK PIPELINE
                # =====================================================

                if source["source"] == "zeek":

                    # -------------------------------------------------
                    # Decode Zeek events
                    # -------------------------------------------------
                    zeek_events = process_zeek_bytes(data, log_type)

                    if not zeek_events:
                        print(f"[MAIN] No valid Zeek events decoded from {log_type}")
                        continue

                    # -------------------------------------------------
                    # Semantic mapping
                    # -------------------------------------------------
                    semantic_results = map_zeek_events(zeek_events, semantic_engine)

                    # -------------------------------------------------
                    # Correlation detection
                    # -------------------------------------------------
                    correlation_results = detect_correlation(zeek_events)

                    print(f"[MAIN] Semantic mappings: {len(semantic_results.get('semantic_results', []))}")
                    print(f"[MAIN] Correlation detections: {len(correlation_results)}")

                    # -------------------------------------------------
                    # Store normalized Zeek events
                    # -------------------------------------------------
                    event_store.store_events(zeek_events, log_type)

                    print(f"[MAIN] Stored {len(zeek_events)} events from {log_type}")

                # =====================================================
                # 4. WAZUH PIPELINE — DECODE & ACCUMULATE ONLY
                # =====================================================

                elif source["source"] == "wazuh":

                    wazuh_events = process_wazuh_bytes(data, log_type)

                    if not wazuh_events:
                        print(f"[MAIN] No valid Wazuh events decoded from {log_type}")
                        continue

                    # Accumulate for deduplicated mapping later
                    all_wazuh_events.extend(wazuh_events)

                    # -------------------------------------------------
                    # Store normalized Wazuh events (per source)
                    # -------------------------------------------------
                    event_store.store_events(wazuh_events, log_type)
                    print(f"[MAIN] Stored {len(wazuh_events)} events from {log_type}")

                # =====================================================
                # 5. COMMIT OFFSET
                # =====================================================

                collector.commit_offset(
                    result["source_id"],
                    result["new_offset"],
                    result["inode"]
                )

                print(f"[MAIN] Offset committed: {result['new_offset']}")

            except Exception as error:

                print(f"[{source['id']}] ERROR: {error}")

                # IMPORTANT:
                # Do NOT commit the offset when processing fails.
                # The same bytes will be retried during the next execution.

        # ============================================================
        # 6. WAZUH DEDUPLICATED MAPPING
        # ============================================================

        if all_wazuh_events:

            print()
            print(
                f"[MAIN] Deduplicating "
                f"{len(all_wazuh_events)} Wazuh events "
                f"across all sources..."
            )

            seen_ids = set()
            unique_wazuh_events = []
            duplicates_removed = 0

            for event in all_wazuh_events:

                decoded_fields = event.get("decoded_fields", {})

                # Handle both live and stored event structures
                if "decoded_fields" in decoded_fields:
                    decoded_fields = decoded_fields.get("decoded_fields", {})

                ev_id = (
                    decoded_fields.get("id")
                    or event.get("id")
                )

                if ev_id:
                    if ev_id in seen_ids:
                        duplicates_removed += 1
                        continue
                    seen_ids.add(ev_id)

                unique_wazuh_events.append(event)

            print(
                f"[MAIN] Removed {duplicates_removed} duplicates. "
                f"Mapping {len(unique_wazuh_events)} unique events..."
            )

            mapped_wazuh_events = map_wazuh_events(unique_wazuh_events)

            print(
                f"[MAIN] Wazuh semantic mappings: "
                f"{len(mapped_wazuh_events)}"
            )

    finally:

        collector.ssh.close()


if __name__ == "__main__":
    main()