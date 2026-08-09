from pathlib import Path

from .ssh_client import SSHClient
from .remote_reader import RemoteReader
from .offset_store import OffsetStore
from .source_registry import SourceRegistry

BASE_DIR = Path(__file__).resolve().parent

CONFIG_PATH = (
    BASE_DIR /
    "config" /
    "sources.json"
)

OFFSET_PATH = (
    BASE_DIR /
    "state" /
    "offsets.json"
)


class Collector:

    def __init__(self):

        self.ssh = SSHClient()

        self.reader = RemoteReader(self.ssh)

        self.offset_store = OffsetStore(OFFSET_PATH)

        self.registry = SourceRegistry(CONFIG_PATH)

    def collect_source(self, source):

        source_id = source["id"]
        remote_path = source["remote_path"]

        print(
            f"\n[{source_id}] "
            f"Checking {remote_path}"
        )

        state = self.offset_store.get(
            source_id
        )

        saved_offset = state["offset"]
        saved_inode = state["inode"]

        file_info = self.reader.get_file_info(
            remote_path
        )

        current_inode = file_info["inode"]
        current_size = file_info["size"]

        # Detect log rotation
        if (
            saved_inode is not None
            and current_inode != saved_inode
        ):
            print(
                f"[{source_id}] "
                "Log rotation detected"
            )

            saved_offset = 0

        # Detect truncation
        elif current_size < saved_offset:

            print(
                f"[{source_id}] "
                "File size decreased. "
                "Resetting offset."
            )

            saved_offset = 0

        data, new_offset, file_info = (
            self.reader.read_new_data(
                remote_path,
                saved_offset
            )
        )

        if not data:

            print(
                f"[{source_id}] "
                "No new data."
            )

            # Update inode only if needed.
            self.offset_store.set(
                source_id,
                saved_offset,
                current_inode
            )

            return None

        print(
            f"[{source_id}] "
            f"Received {len(data)} bytes"
        )

        print(
            f"[{source_id}] "
            f"Offset: "
            f"{saved_offset} -> {new_offset}"
        )

        # ------------------------------------------------
        # IMPORTANT
        # Later this data goes to the decoder.
        # For now we only print it.
        # ------------------------------------------------

        return {
            "data": data,
            "source_id": source_id,
            "log_type": source["log_type"],
            "source": source["source"],
            "new_offset": new_offset,
            "inode": current_inode
        }

    def commit_offset(self, source_id, offset, inode):

        self.offset_store.set(source_id, offset, inode)



if __name__ == "__main__":

    collector = Collector()

    collector.run_once()