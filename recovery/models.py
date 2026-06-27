from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple


class ScanStatus(str, Enum):
    IDLE = "idle"
    SCANNING = "scanning"
    STOPPING = "stopping"
    COMPLETE = "complete"
    ERROR = "error"


class RecoveryStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"


class FileCategory(str, Enum):
    IMAGE = "image"
    VIDEO = "video"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    OTHER = "other"


@dataclass(frozen=True)
class PartitionInfo:
    index: int
    start_byte: int
    size_bytes: int
    type_label: str
    name: str = ""
    scheme: str = ""

    @property
    def end_byte(self) -> int:
        return self.start_byte + self.size_bytes

    @property
    def display_label(self) -> str:
        title = self.name or self.type_label or "Partition"
        size_mb = self.size_bytes / (1024 * 1024)
        return f"{title} — {size_mb:.1f} MB @ 0x{self.start_byte:x}"


@dataclass(frozen=True)
class VolumeInfo:
    device_id: str
    name: str
    size_bytes: int
    mount_point: Optional[str]
    file_system: Optional[str]
    is_removable: bool
    is_internal: bool
    whole_disk: bool
    is_disk_image: bool = False
    image_path: Optional[str] = None
    partitions: Tuple[PartitionInfo, ...] = ()
    scan_start_byte: int = 0
    scan_size_bytes: Optional[int] = None

    @property
    def scan_end_byte(self) -> int:
        if self.scan_size_bytes is None:
            return self.size_bytes
        return self.scan_start_byte + self.scan_size_bytes

    @property
    def scan_byte_count(self) -> int:
        return max(0, self.scan_end_byte - self.scan_start_byte)

    @property
    def is_partition_scan(self) -> bool:
        return self.scan_start_byte > 0 or self.scan_size_bytes is not None

    @property
    def display_name(self) -> str:
        size_gb = self.scan_byte_count / (1024**3)
        if self.is_disk_image:
            base = f"[Image] {self.name} — {size_gb:.1f} GB [{self.image_path}]"
        else:
            mount = f" @ {self.mount_point}" if self.mount_point else " (unmounted)"
            base = f"{self.name} — {size_gb:.1f} GB{mount} [{self.device_id}]"
        if self.is_partition_scan:
            return f"{base} (partition @ 0x{self.scan_start_byte:x})"
        return base

    @property
    def raw_device(self) -> str:
        """Raw character device path for block-level reads."""
        if self.is_disk_image:
            return self.image_path or self.device_id
        base = self.device_id.replace("/dev/", "")
        if base.startswith("disk") and not base.startswith("rdisk"):
            return f"/dev/r{base}"
        return self.device_id

    @property
    def read_path(self) -> str:
        """Path used for sequential reads during scanning and recovery."""
        if self.is_disk_image and self.image_path:
            return self.image_path
        return self.raw_device


@dataclass
class FoundFile:
    offset: int
    size: int
    extension: str
    category: FileCategory
    signature_name: str
    source_device: str
    confidence: str = "medium"
    preview_note: str = ""
    created_at: Optional[float] = None
    modified_at: Optional[float] = None
    selected: bool = field(default=False, compare=False)

    @property
    def filename(self) -> str:
        return f"recovered_{self.offset:012x}.{self.extension}"

    @property
    def size_human(self) -> str:
        return format_bytes(self.size)

    @property
    def category_label(self) -> str:
        return self.category.value.title()

    @property
    def timestamp_display(self) -> str:
        from recovery.timestamps import format_timestamp

        if self.created_at is not None:
            return format_timestamp(self.created_at)
        return format_timestamp(self.modified_at)

    @property
    def timestamp_source(self) -> str:
        if self.created_at is not None:
            return "created"
        if self.modified_at is not None:
            return "modified"
        return "unknown"


def format_bytes(size: int) -> str:
    value = float(max(0, size))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


@dataclass
class ScanProgress:
    status: ScanStatus = ScanStatus.IDLE
    bytes_scanned: int = 0
    total_bytes: int = 0
    files_found: int = 0
    current_message: str = ""
    error: Optional[str] = None
    elapsed_seconds: float = 0.0
    bytes_per_second: float = 0.0
    eta_seconds: Optional[float] = None

    @property
    def percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        value = (self.bytes_scanned / self.total_bytes) * 100.0
        if not math.isfinite(value):
            return 0.0
        return min(100.0, max(0.0, value))

    @property
    def eta_human(self) -> str:
        return format_duration(self.eta_seconds)

    @property
    def elapsed_human(self) -> str:
        return format_duration(self.elapsed_seconds)

    @property
    def progress_summary(self) -> str:
        parts = [f"{self.percent:.1f}%"]
        if (
            self.eta_seconds is not None
            and math.isfinite(self.eta_seconds)
            and self.status == ScanStatus.SCANNING
        ):
            parts.append(f"ETA {self.eta_human}")
        parts.append(f"{self.files_found} found")
        if self.elapsed_seconds > 0 and math.isfinite(self.elapsed_seconds):
            parts.append(f"elapsed {self.elapsed_human}")
        return " — ".join(parts)


@dataclass
class RecoveryProgress:
    status: RecoveryStatus = RecoveryStatus.IDLE
    total: int = 0
    completed: int = 0
    succeeded: int = 0
    failed: int = 0
    destination: str = ""
    current_file: str = ""
    error: Optional[str] = None

    @property
    def percent(self) -> float:
        if self.total <= 0:
            return 0.0
        value = (self.completed / self.total) * 100.0
        if not math.isfinite(value):
            return 0.0
        return min(100.0, max(0.0, value))


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None or seconds < 0 or not math.isfinite(seconds):
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"
