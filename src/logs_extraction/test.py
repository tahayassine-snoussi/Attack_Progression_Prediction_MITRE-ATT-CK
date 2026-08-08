from ssh_client import SSHClient
from remote_reader import RemoteReader


REMOTE_PATH = "/opt/zeek/logs/current/conn.log"

ssh = SSHClient()
reader = RemoteReader(ssh)

try:
    # Start from the beginning ONLY for this first test
    offset = 363123

    data, new_offset, info = reader.read_new_data(
        REMOTE_PATH,
        offset
    )

    print("File size:", info["size"])
    print("Old offset:", offset)
    print("New offset:", new_offset)
    print("Bytes received:", len(data))

finally:
    ssh.close()