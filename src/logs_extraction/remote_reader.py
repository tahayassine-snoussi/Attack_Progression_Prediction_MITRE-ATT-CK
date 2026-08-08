class RemoteReader:

    def __init__(self, ssh_client):
        self.ssh = ssh_client

    def get_file_info(self, remote_path):
        return self.ssh.stat(remote_path)

    def read_new_data(self, remote_path, offset):

        file_info = self.get_file_info(
            remote_path
        )

        current_size = file_info["size"]

        # No new data
        if current_size <= offset:
            return b"", offset, file_info

        data = self.ssh.read_from_offset(
            remote_path,
            offset
        )

        new_offset = offset + len(data)

        return data, new_offset, file_info