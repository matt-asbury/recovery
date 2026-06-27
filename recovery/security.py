from __future__ import annotations

import os
import socket
import stat
from typing import Union

MAX_JSON_BODY_BYTES = 1 * 1024 * 1024


class SecurityError(ValueError):
    """Raised when a path or request fails security validation."""


def is_local_client(address: Union[str, bytes]) -> bool:
    """Return True when the client address is loopback."""
    if isinstance(address, bytes):
        host = address.decode("utf-8", errors="ignore")
    else:
        host = str(address)
    if host in {"127.0.0.1", "::1", "localhost"}:
        return True
    if host.startswith("127."):
        return True
    try:
        packed = socket.inet_pton(socket.AF_INET6, host)
        return packed == socket.inet_pton(socket.AF_INET6, "::1")
    except OSError:
        return False


def validate_recovery_destination(path: str) -> str:
    """Resolve and validate a recovery output directory."""
    cleaned = path.strip()
    if not cleaned:
        raise SecurityError("Destination path is required")

    expanded = os.path.abspath(os.path.expanduser(cleaned))
    resolved = os.path.realpath(expanded) if os.path.exists(expanded) else expanded

    if os.path.exists(resolved):
        if os.path.islink(expanded) and not os.path.isdir(resolved):
            raise SecurityError("Destination symlink must point to a directory")
        if not os.path.isdir(resolved):
            raise SecurityError("Destination must be a directory")
        if _is_device_special(resolved):
            raise SecurityError("Destination cannot be a device special file")
    else:
        parent = os.path.dirname(resolved)
        if not parent or not os.path.isdir(parent):
            raise SecurityError("Destination parent directory does not exist")

    return resolved


def safe_filename(filename: str) -> str:
    """Return a basename safe for writing inside a destination directory."""
    cleaned = filename.strip()
    if not cleaned or cleaned in {".", ".."}:
        raise SecurityError("Invalid filename")
    if ".." in cleaned or any(separator in cleaned for separator in ("/", "\\", "\0")):
        raise SecurityError("Invalid filename")
    name = os.path.basename(cleaned)
    if not name or name in {".", ".."}:
        raise SecurityError("Invalid filename")
    return name


def safe_destination_path(directory: str, filename: str) -> str:
    """Build a destination file path guaranteed to stay within directory."""
    base = validate_recovery_destination(directory)
    name = safe_filename(filename)
    base_resolved = os.path.realpath(base) if os.path.exists(base) else os.path.abspath(base)
    final_path = os.path.abspath(os.path.join(base_resolved, name))
    if not is_path_within(base_resolved, final_path):
        raise SecurityError("Recovery path escapes destination directory")
    return final_path


def validate_readable_file_path(path: str) -> str:
    """Validate a user-supplied path to a regular readable file."""
    cleaned = path.strip()
    if not cleaned:
        raise SecurityError("Path is required")
    expanded = os.path.abspath(os.path.expanduser(cleaned))
    resolved = os.path.realpath(expanded)
    if not os.path.isfile(resolved):
        raise FileNotFoundError(f"File not found: {cleaned}")
    if os.path.islink(expanded) and not os.path.isfile(resolved):
        raise SecurityError("Symlink does not resolve to a readable file")
    return resolved


def is_path_within(base_directory: str, target_path: str) -> bool:
    base = os.path.realpath(base_directory)
    target = os.path.realpath(target_path)
    return target == base or target.startswith(base + os.sep)


def _is_device_special(path: str) -> bool:
    mode = os.stat(path).st_mode
    return stat.S_ISBLK(mode) or stat.S_ISCHR(mode)
