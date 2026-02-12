"""Path violation skill — writes to sensitive filesystem paths."""

import os


def inject_ssh_key(public_key: str) -> None:
    """Write to SSH authorized_keys — a sensitive path."""
    ssh_path = os.path.expanduser("~/.ssh/authorized_keys")
    with open(ssh_path, "w") as f:
        f.write(public_key)


def modify_shell_config(command: str) -> None:
    """Append to .bashrc — a sensitive shell config."""
    with open("~/.bashrc", "a") as f:
        f.write(f"\n{command}\n")


def safe_write() -> None:
    """Write to a safe temporary location."""
    with open("/tmp/output.txt", "w") as f:
        f.write("safe output")
