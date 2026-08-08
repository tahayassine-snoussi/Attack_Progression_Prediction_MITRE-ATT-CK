import os
import paramiko
from dotenv import load_dotenv


class SSHClient:
    def __init__(self):
        load_dotenv()

        self.host = os.getenv("IP_ADDRESS")
        self.username = os.getenv("SSH_USERNAME", "taha")
        self.password = os.getenv("SSH_PASSWORD")
        self.sudo_password = os.getenv("SUDO_PASSWORD")
        self.port = int(os.getenv("SSH_PORT", 22))

        if not self.host:
            raise ValueError("IP_ADDRESS is missing from .env")

        if not self.password:
            raise ValueError("SSH_PASSWORD is missing from .env")

        if not self.sudo_password:
            raise ValueError("SUDO_PASSWORD is missing from .env")

        self.client = None

    def connect(self):
        if self.client is not None:
            return

        self.client = paramiko.SSHClient()

        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=10
        )

    def execute(self, command):
        self.connect()

        stdin, stdout, stderr = self.client.exec_command(command)

        return (
            stdout.read().decode(errors="replace"),
            stderr.read().decode(errors="replace")
        )

    def execute_sudo(self, command):
        self.connect()

        sudo_command = f"sudo -S -p '' {command}"

        stdin, stdout, stderr = self.client.exec_command(
            sudo_command
        )

        stdin.write(self.sudo_password + "\n")
        stdin.flush()

        output = stdout.read().decode(errors="replace")
        error = stderr.read().decode(errors="replace")

        return output, error

    def stat(self, remote_path):
        output, error = self.execute_sudo(
            f"stat -c '%s %Y %i' '{remote_path}'"
        )

        if error.strip():
            raise PermissionError(error.strip())

        parts = output.strip().split()

        if len(parts) != 3:
            raise RuntimeError(
                f"Unexpected stat output: {output}"
            )

        return {
            "size": int(parts[0]),
            "mtime": int(parts[1]),
            "inode": int(parts[2])
        }

    def read_from_offset(self, remote_path, offset):
        command = (
            f"dd if='{remote_path}' "
            f"bs=1 skip={offset} "
            f"status=none"
        )

        output, error = self.execute_sudo(command)

        if error.strip():
            raise PermissionError(error.strip())

        return output.encode()

    def close(self):
        if self.client is not None:
            self.client.close()
            self.client = None