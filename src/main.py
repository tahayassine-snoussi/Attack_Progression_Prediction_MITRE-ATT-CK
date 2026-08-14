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

                    zeek_events = process_zeek_bytes(
                        data,
                        log_type
                    )

                    if not zeek_events:
                        print(
                            f"[MAIN] No valid Zeek events "
                            f"decoded from {log_type}"
                        )

                        continue

                    # -------------------------------------------------
                    # Semantic mapping
                    # -------------------------------------------------

                    semantic_results = map_zeek_events(
                        zeek_events,
                        semantic_engine
                    )

                    # -------------------------------------------------
                    # Correlation detection
                    # -------------------------------------------------
                    
                    correlation_results = detect_correlation(
                        zeek_events
                    )

                    print(
                        f"[MAIN] Semantic mappings: "
                        f"{len(semantic_results.get('semantic_results', []))}"
                    )

                    print(
                        f"[MAIN] Correlation detections: "
                        f"{len(correlation_results)}"
                    )

                    # -------------------------------------------------
                    # Store normalized Zeek events
                    # -------------------------------------------------

                    event_store.store_events(
                        zeek_events,
                        log_type
                    )

                    print(
                        f"[MAIN] Stored "
                        f"{len(zeek_events)} events from {log_type}"
                    )

                # =====================================================
                # 4. WAZUH PIPELINE
                # =====================================================

                elif source["source"] == "wazuh":

                    wazuh_events = process_wazuh_bytes(
                        data,
                        log_type
                    )

                    if not wazuh_events:
                        print(
                            f"[MAIN] No valid Wazuh events "
                            f"decoded from {log_type}"
                        )

                        continue

                    mapped_wazuh_events = map_wazuh_events(
                        wazuh_events
                    )

                    # -------------------------------------------------
                    # Store normalized Wazuh events
                    # -------------------------------------------------

                    event_store.store_events(
                        wazuh_events,
                        log_type
                    )

                    print(
                        f"[MAIN] Stored "
                        f"{len(wazuh_events)} events from {log_type}"
                    )

                # =====================================================
                # 5. COMMIT OFFSET
                # =====================================================

                collector.commit_offset(
                    result["source_id"],
                    result["new_offset"],
                    result["inode"]
                )

                print(
                    f"[MAIN] Offset committed: "
                    f"{result['new_offset']}"
                )

            except Exception as error:

                print(
                    f"[{source['id']}] ERROR: {error}"
                )

                # IMPORTANT:
                #
                # Do NOT commit the offset when processing fails.
                #
                # The same bytes will be retried during the
                # next execution.

    finally:

        collector.ssh.close()


if __name__ == "__main__":
    main()