from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Callable, Optional

from recovery.models import FoundFile
from recovery.device_io import write_bytes
from recovery.security import safe_destination_path, safe_filename, validate_recovery_destination


@dataclass
class RecoveryResult:
    source: FoundFile
    destination: str
    success: bool
    error: Optional[str] = None


def recover_files(
    files: list[FoundFile],
    destination_dir: str,
    *,
    on_progress: Optional[Callable[[int, int, RecoveryResult], None]] = None,
) -> list[RecoveryResult]:
    """Copy or carve selected files to a destination directory."""
    destination_dir = validate_recovery_destination(destination_dir)
    os.makedirs(destination_dir, exist_ok=True)
    results: list[RecoveryResult] = []
    total = len(files)

    for index, item in enumerate(files, start=1):
        dest_path = _unique_path(destination_dir, item.filename)
        try:
            if item.preview_note and os.path.isfile(item.preview_note):
                shutil.copy2(item.preview_note, dest_path)
            else:
                _carve_file(item, dest_path)
            result = RecoveryResult(source=item, destination=dest_path, success=True)
        except OSError as exc:
            result = RecoveryResult(
                source=item,
                destination=dest_path,
                success=False,
                error=str(exc),
            )

        results.append(result)
        if on_progress:
            on_progress(index, total, result)

    return results


def _carve_file(item: FoundFile, dest_path: str) -> None:
    with open(dest_path, "wb") as dst:
        written = write_bytes(item.source_device, item.offset, item.size, dst)
        if written <= 0:
            raise OSError(f"No data read from {item.source_device} at 0x{item.offset:x}")


def _unique_path(directory: str, filename: str) -> str:
    base, ext = os.path.splitext(safe_filename(filename))
    candidate = safe_destination_path(directory, f"{base}{ext}")
    counter = 1
    while os.path.exists(candidate):
        candidate = safe_destination_path(directory, f"{base}_{counter}{ext}")
        counter += 1
    return candidate
