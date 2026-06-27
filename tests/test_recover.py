import os
import tempfile

import pytest

from recovery.models import FileCategory, FoundFile
from recovery.recover import recover_files
from recovery.security import SecurityError


def _found_file(source_path: str) -> FoundFile:
    return FoundFile(
        offset=0,
        size=4,
        extension="txt",
        category=FileCategory.OTHER,
        signature_name="Test",
        source_device=source_path,
        confidence="high",
    )


def test_recover_writes_inside_destination() -> None:
    with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
        source = os.path.join(src_dir, "source.bin")
        with open(source, "wb") as handle:
            handle.write(b"data")

        results = recover_files([_found_file(source)], dest_dir)
        assert results[0].success
        assert os.path.isfile(results[0].destination)
        assert results[0].destination.startswith(os.path.realpath(dest_dir))


def test_recover_rejects_invalid_destination() -> None:
    with tempfile.NamedTemporaryFile() as source, tempfile.NamedTemporaryFile() as dest:
        with pytest.raises(SecurityError):
            recover_files([_found_file(source.name)], dest.name)
