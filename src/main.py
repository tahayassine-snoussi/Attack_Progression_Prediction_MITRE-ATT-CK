from logs_extraction.collector import Collector
from pipeline.zeek_pipeline import process_zeek_bytes
from pipeline.wazuh_pipeline import process_wazuh_bytes
from storage.event_store import EventStore


def main():

    collector = Collector()
    event_store = EventStore()

    try:

        for source in collector.registry.get_sources():

            try:

                # =====================================
                # 1. GET NEW BYTES
                # =====================================
                result = collector.collect_source(source)

                if result is None:
                    continue

                # =====================================
                # 2. EXTRACT RESULT INFORMATION
                # =====================================
                data = result["data"]
                log_type = result["log_type"]

                # =====================================
                # 3. DECODE
                # =====================================
                if source["source"] == "zeek":
                    zeek_events = process_zeek_bytes(data, log_type)

                elif source["source"] == "wazuh":
                    wazuh_events = process_wazuh_bytes(data, log_type)

                # =====================================
                # 4. STORE NORMALIZED EVENTS
                # =====================================
                if source["source"] == "zeek":
                    event_store.store_events(zeek_events, log_type)
                    print(f"[MAIN] Stored " f"{len(zeek_events)} events " f"from {log_type}")
                elif source["source"] == "wazuh":
                    event_store.store_events(wazuh_events, log_type)
                    print(f"[MAIN] Stored " f"{len(wazuh_events)} events " f"from {log_type}")

                # =====================================
                
                # 5. COMMIT OFFSET
                # =====================================
                collector.commit_offset(result["source_id"], result["new_offset"], result["inode"])
                print(f"[MAIN] Offset committed: " f"{result['new_offset']}")

            except Exception as error:

                print(f"[{source['id']}] " f"ERROR: {error}")

                # IMPORTANT:
                # Do NOT commit the offset here.
                #
                # The bytes will be retried
                # during the next run.

    finally:

        collector.ssh.close()


if __name__ == "__main__":
    main()