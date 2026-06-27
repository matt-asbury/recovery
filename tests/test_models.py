from recovery.models import (
    FileCategory,
    FoundFile,
    RecoveryProgress,
    RecoveryStatus,
    ScanProgress,
    ScanStatus,
    format_bytes,
    format_duration,
)


def test_format_bytes() -> None:
    assert format_bytes(512) == "512 B"
    assert format_bytes(1536) == "1.5 KB"


def test_format_duration() -> None:
    assert format_duration(45) == "45s"
    assert format_duration(125) == "2m 5s"
    assert format_duration(None) == "—"


def test_scan_progress_percent_clamps() -> None:
    progress = ScanProgress(
        status=ScanStatus.SCANNING,
        bytes_scanned=500,
        total_bytes=1000,
    )
    assert progress.percent == 50.0


def test_recovery_progress_percent() -> None:
    progress = RecoveryProgress(
        status=RecoveryStatus.RUNNING,
        total=10,
        completed=4,
    )
    assert progress.percent == 40.0


def test_found_file_defaults_not_selected() -> None:
    found = FoundFile(
        offset=0x100,
        size=1024,
        extension="jpg",
        category=FileCategory.IMAGE,
        signature_name="JPEG",
        source_device="/dev/rdisk1",
    )
    assert found.selected is False
    assert found.filename == "recovered_000000000100.jpg"


def test_filesystem_file_uses_original_filename() -> None:
    found = FoundFile(
        offset=0,
        size=100,
        extension="jpg",
        category=FileCategory.IMAGE,
        signature_name="Filesystem",
        source_device="/Volumes/USB/vacation.jpg",
        preview_note="/Volumes/USB/vacation.jpg",
        source_kind="filesystem",
    )
    assert found.filename == "vacation.jpg"
    assert found.is_filesystem_file
