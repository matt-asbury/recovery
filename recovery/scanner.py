from __future__ import annotations

import math
import os
import threading
import time
from typing import Callable, Optional

from recovery.filesystem import walk_filesystem
from recovery.models import FoundFile, ScanProgress, ScanStatus, VolumeInfo
from recovery.signatures import SIGNATURES, FileSignature
from recovery.timestamps import HEADER_BYTES, extract_timestamps
from recovery.validation import validate_carved


DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
DEFAULT_OVERLAP = 512 * 1024
DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024
DEFAULT_MIN_FILE_SIZE = 256


class DeepScanner:
    """Raw block scanner that carves files by magic-byte signatures."""

    def __init__(
        self,
        volume: VolumeInfo,
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        overlap: int = DEFAULT_OVERLAP,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        min_file_size: int = DEFAULT_MIN_FILE_SIZE,
        categories: Optional[set[str]] = None,
        carve_regions: Optional[list[tuple[int, int]]] = None,
    ) -> None:
        self.volume = volume
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.max_file_size = max_file_size
        self.min_file_size = min_file_size
        self.categories = categories
        self.carve_regions = carve_regions

        self.progress = ScanProgress()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._found: list[FoundFile] = []
        self._seen_offsets: set[int] = set()
        self._rejected_count: int = 0
        self._start_time: float = 0.0

    @property
    def results(self) -> list[FoundFile]:
        return list(self._found)

    @property
    def rejected_count(self) -> int:
        return self._rejected_count

    def start(
        self,
        on_file: Optional[Callable[[FoundFile], None]] = None,
        on_progress: Optional[Callable[[ScanProgress], None]] = None,
    ) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("Scan already running")

        self._stop_event.clear()
        self._found.clear()
        self._seen_offsets.clear()
        self._rejected_count = 0
        self.progress = ScanProgress(status=ScanStatus.SCANNING)

        self._thread = threading.Thread(
            target=self._run,
            args=(on_file, on_progress),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self.progress.status = ScanStatus.STOPPING
        self._stop_event.set()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def _run(
        self,
        on_file: Optional[Callable[[FoundFile], None]],
        on_progress: Optional[Callable[[ScanProgress], None]],
    ) -> None:
        device = self.volume.read_path
        try:
            media_size = self.volume.size_bytes or os.path.getsize(device)
        except OSError as exc:
            self.progress.status = ScanStatus.ERROR
            if self.volume.is_disk_image:
                self.progress.error = f"Cannot read disk image {device}: {exc}"
            else:
                self.progress.error = (
                    f"Cannot access {device}: {exc}. "
                    "Try running with sudo: sudo python -m recovery"
                )
            self._notify_progress(on_progress)
            return

        scan_start = max(0, self.volume.scan_start_byte)
        scan_size = self.volume.scan_size_bytes
        if scan_size is None:
            scan_size = max(0, media_size - scan_start)
        else:
            scan_size = min(scan_size, max(0, media_size - scan_start))

        if scan_size <= 0:
            self.progress.status = ScanStatus.ERROR
            self.progress.error = "Selected scan region is empty or beyond media size."
            self._notify_progress(on_progress)
            return

        regions = self._resolve_carve_regions(scan_start, scan_size)
        total = sum(size for _, size in regions)
        self.progress.total_bytes = total
        label = self.volume.name if self.volume.is_disk_image else device
        if self.carve_regions is not None:
            self.progress.current_message = (
                f"Carving {len(regions)} unallocated region(s) on {label}..."
            )
        elif self.volume.is_partition_scan:
            self.progress.current_message = (
                f"Scanning {label} (0x{scan_start:x}–0x{scan_start + scan_size:x})..."
            )
        else:
            self.progress.current_message = f"Scanning {label}..."
        self._start_time = time.monotonic()

        try:
            bytes_scanned = 0
            for region_start, region_size in regions:
                if self._stop_event.is_set():
                    break

                region_end = region_start + region_size
                with open(device, "rb", buffering=0) as handle:
                    handle.seek(region_start)
                    offset = region_start
                    carry = b""

                    while offset < region_end and not self._stop_event.is_set():
                        read_size = min(self.chunk_size, region_end - offset)
                        chunk = handle.read(read_size)
                        if not chunk:
                            break

                        window = carry + chunk
                        base_offset = offset - len(carry)

                        self._scan_window(window, base_offset, on_file)

                        carry = window[-self.overlap :] if len(window) > self.overlap else window
                        offset += len(chunk)

                        bytes_scanned += len(chunk)
                        self.progress.bytes_scanned = bytes_scanned
                        self._update_timing()
                        self._notify_progress(on_progress)

            if self._stop_event.is_set():
                self.progress.status = ScanStatus.COMPLETE
                self.progress.current_message = "Scan stopped by user."
            else:
                self.progress.status = ScanStatus.COMPLETE
                rejected_note = ""
                if self._rejected_count:
                    rejected_note = f" ({self._rejected_count:,} low-quality hits filtered)"
                self.progress.current_message = (
                    f"Scan complete. Found {len(self._found)} recoverable file(s){rejected_note}."
                )
        except PermissionError:
            self.progress.status = ScanStatus.ERROR
            if self.volume.is_disk_image:
                self.progress.error = f"Permission denied reading disk image: {device}"
            else:
                self.progress.error = (
                    f"Permission denied reading {device}. "
                    "Raw disk access requires administrator privileges:\n"
                    "  sudo python -m recovery"
                )
        except OSError as exc:
            self.progress.status = ScanStatus.ERROR
            self.progress.error = f"Error reading {device}: {exc}"
        finally:
            self._notify_progress(on_progress)

    def _resolve_carve_regions(self, scan_start: int, scan_size: int) -> list[tuple[int, int]]:
        scan_end = scan_start + scan_size
        if self.carve_regions is None:
            return [(scan_start, scan_size)]

        clipped: list[tuple[int, int]] = []
        for start, size in self.carve_regions:
            end = start + size
            clip_start = max(start, scan_start)
            clip_end = min(end, scan_end)
            if clip_end > clip_start:
                clipped.append((clip_start, clip_end - clip_start))
        return clipped or [(scan_start, scan_size)]

    def _scan_window(
        self,
        data: bytes,
        base_offset: int,
        on_file: Optional[Callable[[FoundFile], None]],
    ) -> None:
        for signature in SIGNATURES:
            if self.categories and signature.category.value not in self.categories:
                continue

            start = 0
            while True:
                idx = data.find(signature.pattern, start)
                if idx == -1:
                    break
                start = idx + 1

                absolute_offset = base_offset + idx
                if absolute_offset in self._seen_offsets:
                    continue

                size = signature.estimate_size(data, idx, self.max_file_size)
                if size is None or size < self.min_file_size:
                    continue

                if signature.name == "DOCX" and not _looks_like_docx(data, idx, size):
                    continue
                if signature.name == "ZIP" and _looks_like_docx(data, idx, size):
                    continue

                snippet = data[idx : idx + size]
                validation = validate_carved(
                    snippet,
                    signature.extension,
                    signature.name,
                    signature.confidence,
                )
                if not validation.accepted:
                    self._rejected_count += 1
                    continue

                self._seen_offsets.add(absolute_offset)
                header_end = min(len(data), idx + min(size, HEADER_BYTES))
                times = extract_timestamps(data[idx:header_end], signature.extension)
                found = FoundFile(
                    offset=absolute_offset,
                    size=size,
                    extension=signature.extension,
                    category=signature.category,
                    signature_name=signature.name,
                    source_device=self.volume.read_path,
                    confidence=validation.confidence,
                    created_at=times.created,
                    modified_at=times.modified,
                    source_kind="carved",
                )
                self._found.append(found)
                self.progress.files_found = len(self._found)

                if on_file:
                    on_file(found)

    def _update_timing(self) -> None:
        elapsed = time.monotonic() - self._start_time
        self.progress.elapsed_seconds = elapsed
        if elapsed <= 0 or self.progress.bytes_scanned <= 0:
            self.progress.bytes_per_second = 0.0
            self.progress.eta_seconds = None
            return

        rate = self.progress.bytes_scanned / elapsed
        self.progress.bytes_per_second = rate if math.isfinite(rate) else 0.0
        remaining = max(0, self.progress.total_bytes - self.progress.bytes_scanned)
        if rate > 0 and math.isfinite(rate):
            eta = remaining / rate
            self.progress.eta_seconds = eta if math.isfinite(eta) else None
        else:
            self.progress.eta_seconds = None

    def _notify_progress(
        self,
        on_progress: Optional[Callable[[ScanProgress], None]],
    ) -> None:
        if on_progress:
            on_progress(self.progress)


def _looks_like_docx(data: bytes, start: int, size: int) -> bool:
    end = min(len(data), start + min(size, 4096))
    snippet = data[start:end]
    return b"word/" in snippet or b"[Content_Types].xml" in snippet


def quick_scan_mount(
    mount_point: str,
    *,
    categories: Optional[set[str]] = None,
) -> list[FoundFile]:
    """Walk a mounted filesystem for existing files (non-destructive listing)."""
    return walk_filesystem(mount_point, categories=categories)
