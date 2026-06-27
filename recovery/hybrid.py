from __future__ import annotations

import threading
from typing import Callable, Optional

from recovery.filesystem import unallocated_regions, walk_filesystem
from recovery.models import FoundFile, ScanProgress, ScanStatus, VolumeInfo
from recovery.scanner import DeepScanner


class HybridScanner:
    """Filesystem walk plus carving of unallocated space on raw media."""

    def __init__(
        self,
        volume: VolumeInfo,
        *,
        categories: Optional[set[str]] = None,
    ) -> None:
        self.volume = volume
        self.categories = categories
        self.progress = ScanProgress(status=ScanStatus.SCANNING)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._deep: Optional[DeepScanner] = None
        self._filesystem_count = 0
        self._carved_count = 0
        self.rejected_count = 0

    def start(
        self,
        on_file: Optional[Callable[[FoundFile], None]] = None,
        on_progress: Optional[Callable[[ScanProgress], None]] = None,
    ) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("Scan already running")

        self._stop_event.clear()
        self._filesystem_count = 0
        self._carved_count = 0
        self.rejected_count = 0
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
        if self._deep is not None:
            self._deep.stop()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def _run(
        self,
        on_file: Optional[Callable[[FoundFile], None]],
        on_progress: Optional[Callable[[ScanProgress], None]],
    ) -> None:
        try:
            if self.volume.mount_point and not self._stop_event.is_set():
                self.progress.current_message = "Hybrid scan: walking filesystem..."
                self._notify(on_progress)
                files = walk_filesystem(
                    self.volume.mount_point,
                    categories=self.categories,
                )
                for found in files:
                    if self._stop_event.is_set():
                        break
                    self._filesystem_count += 1
                    self.progress.files_found = self._filesystem_count
                    if on_file:
                        on_file(found)

            if self._stop_event.is_set():
                self._complete_stopped(on_progress)
                return

            if self.volume.encryption.blocks_raw_carve:
                carved_note = "raw carving skipped (encrypted volume)"
                fs_note = (
                    f"{self._filesystem_count} filesystem"
                    if self._filesystem_count
                    else "no filesystem files"
                )
                self.progress.status = ScanStatus.COMPLETE
                self.progress.current_message = (
                    f"Hybrid scan complete. Found {fs_note}; {carved_note}. "
                    f"{self.volume.encryption.workflow}"
                )
                self._notify(on_progress)
                return

            regions = unallocated_regions(self.volume)
            if regions is not None and not regions:
                self.progress.status = ScanStatus.COMPLETE
                self.progress.current_message = (
                    f"Hybrid scan complete. Found {self._filesystem_count} filesystem file(s); "
                    "no unallocated space detected on FAT32."
                )
                self._notify(on_progress)
                return

            if regions is None:
                self.progress.current_message = (
                    "Hybrid scan: carving full partition "
                    "(free-space map unavailable for this filesystem)..."
                )
            else:
                free_bytes = sum(size for _, size in regions)
                self.progress.current_message = (
                    f"Hybrid scan: carving {free_bytes:,} bytes of unallocated space..."
                )
            self._notify(on_progress)

            self._deep = DeepScanner(
                self.volume,
                categories=self.categories,
                carve_regions=regions,
            )

            def on_carved(found: FoundFile) -> None:
                self._carved_count += 1
                self.progress.files_found = self._filesystem_count + self._carved_count
                if on_file:
                    on_file(found)

            def on_deep_progress(progress: ScanProgress) -> None:
                self.progress.bytes_scanned = progress.bytes_scanned
                self.progress.total_bytes = progress.total_bytes
                self.progress.elapsed_seconds = progress.elapsed_seconds
                self.progress.bytes_per_second = progress.bytes_per_second
                self.progress.eta_seconds = progress.eta_seconds
                if progress.status == ScanStatus.ERROR:
                    self.progress.status = ScanStatus.ERROR
                    self.progress.error = progress.error
                self._notify(on_progress)

            self._deep.start(on_file=on_carved, on_progress=on_deep_progress)
            self._deep.join()

            if self._deep.progress.status == ScanStatus.ERROR:
                self.progress.status = ScanStatus.ERROR
                self.progress.error = self._deep.progress.error
            elif self._stop_event.is_set():
                self._complete_stopped(on_progress)
                return

            self.rejected_count = self._deep.rejected_count
            rejected_note = (
                f" ({self.rejected_count:,} low-quality hits filtered)"
                if self.rejected_count
                else ""
            )
            carved_note = (
                f"{self._carved_count} carved"
                if self._carved_count
                else "no carved files"
            )
            fs_note = (
                f"{self._filesystem_count} filesystem"
                if self._filesystem_count
                else "no filesystem files"
            )
            self.progress.status = ScanStatus.COMPLETE
            self.progress.current_message = (
                f"Hybrid scan complete. Found {fs_note}, {carved_note}{rejected_note}."
            )
        except OSError as exc:
            self.progress.status = ScanStatus.ERROR
            self.progress.error = str(exc)
        finally:
            self._notify(on_progress)

    def _complete_stopped(self, on_progress: Optional[Callable[[ScanProgress], None]]) -> None:
        self.progress.status = ScanStatus.COMPLETE
        self.progress.current_message = "Hybrid scan stopped by user."
        self._notify(on_progress)

    def _notify(self, on_progress: Optional[Callable[[ScanProgress], None]]) -> None:
        if on_progress:
            on_progress(self.progress)
