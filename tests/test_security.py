import os
import tempfile

import pytest

from recovery.security import (
    SecurityError,
    is_local_client,
    is_path_within,
    safe_destination_path,
    safe_filename,
    validate_recovery_destination,
)


def test_is_local_client() -> None:
    assert is_local_client("127.0.0.1")
    assert is_local_client("127.0.0.2")
    assert is_local_client("::1")
    assert not is_local_client("192.168.1.10")


def test_safe_filename_rejects_traversal() -> None:
    with pytest.raises(SecurityError):
        safe_filename("../etc/passwd")


def test_validate_recovery_destination_requires_directory() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        assert validate_recovery_destination(tmp) == os.path.realpath(tmp)


def test_validate_recovery_destination_rejects_file() -> None:
    with tempfile.NamedTemporaryFile() as tmp:
        with pytest.raises(SecurityError):
            validate_recovery_destination(tmp.name)


def test_safe_destination_path_stays_inside_base() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = safe_destination_path(tmp, "recovered_000001.jpg")
        assert is_path_within(tmp, path)


