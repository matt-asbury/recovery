from __future__ import annotations

import json
import math
import os
import subprocess
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from recovery.file_list import DEFAULT_MIN_CONFIDENCE, DEFAULT_PAGE_SIZE, LARGE_RESULT_THRESHOLD
from recovery.models import (
    FoundFile,
    RecoveryProgress,
    RecoveryStatus,
    ScanProgress,
    ScanStatus,
    VolumeInfo,
)
from recovery.preview import can_preview, preview_description, render_preview
from recovery.recover import RecoveryResult, recover_files
from recovery.results_store import ResultsStore
from recovery.hybrid import HybridScanner
from recovery.scanner import DeepScanner, quick_scan_mount
from recovery.security import (
    MAX_JSON_BODY_BYTES,
    SecurityError,
    is_local_client,
    validate_readable_file_path,
    validate_recovery_destination,
)
from recovery.partitions import partition_to_dict
from recovery.volumes import list_volumes, volume_for_partition, volume_from_image

DEFAULT_PORT = 8765
DEFAULT_DEST = os.path.expanduser("~/RecoveredFiles")


class AppState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.volumes: list[VolumeInfo] = []
        self.results = ResultsStore()
        self.scanner: Optional[DeepScanner | HybridScanner] = None
        self.progress = ScanProgress()
        self.scanning = False
        self.recovery = RecoveryProgress()
        self.recovery_dir = DEFAULT_DEST
        self.include_internal = False

    def refresh_volumes(self) -> None:
        with self.lock:
            disk_volumes = list_volumes(include_internal=self.include_internal)
            images = [v for v in self.volumes if v.is_disk_image]
            self.volumes = images + [v for v in disk_volumes if not v.is_disk_image]

    def add_image(self, path: str) -> VolumeInfo:
        volume = volume_from_image(path)
        with self.lock:
            self.volumes = [volume] + [
                v for v in self.volumes if not v.is_disk_image or v.image_path != path
            ]
        return volume

    def file_to_dict(self, found: FoundFile, index: int) -> dict[str, Any]:
        return {
            "index": index,
            "filename": found.filename,
            "category": found.category.value,
            "extension": found.extension,
            "size_human": found.size_human,
            "timestamp": found.timestamp_display,
            "timestamp_source": found.timestamp_source,
            "confidence": found.confidence,
            "source_kind": found.source_kind,
            "selected": found.selected,
            "offset_display": found.preview_note if found.is_filesystem_file else (found.preview_note or f"0x{found.offset:x}"),
            "can_preview": can_preview(found),
        }

    def file_detail(self, index: int) -> Optional[dict[str, Any]]:
        with self.lock:
            found = self.results.get(index)
            if found is None:
                return None
            payload = self.file_to_dict(found, index)
            payload["description"] = preview_description(found)
            return payload


STATE = AppState()


def run_gui(host: str = "127.0.0.1", port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    STATE.refresh_volumes()
    server = ThreadingHTTPServer((host, port), RecoveryHandler)
    url = f"http://{host}:{port}/"

    print(f"Recovery UI running at {url}")
    if os.geteuid() != 0:
        print("Tip: deep scans of raw disks require sudo — run: sudo ./recovery.sh")
    print("Press Ctrl+C to stop.")

    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


class RecoveryHandler(BaseHTTPRequestHandler):
    server_version = "RecoveryHTTP/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _reject_non_local(self) -> bool:
        if is_local_client(self.client_address[0]):
            return False
        self._respond_json({"error": "Forbidden"}, status=403)
        return True

    def do_GET(self) -> None:
        if self._reject_non_local():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._respond_html(INDEX_HTML)
            return
        if parsed.path == "/api/volumes":
            self._handle_volumes_get()
            return
        if parsed.path == "/api/scan/status":
            self._handle_scan_status()
            return
        if parsed.path == "/api/files":
            self._handle_files_get(parse_qs(parsed.query))
            return
        if parsed.path == "/api/files/summary":
            self._handle_files_summary(parse_qs(parsed.query))
            return
        if parsed.path.startswith("/api/files/") and parsed.path != "/api/files/":
            index_text = parsed.path.rsplit("/", 1)[-1]
            if index_text.isdigit():
                self._handle_file_detail(int(index_text))
                return
        if parsed.path.startswith("/api/preview/"):
            self._handle_preview(parsed.path.rsplit("/", 1)[-1])
            return
        self._respond_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        if self._reject_non_local():
            return
        parsed = urlparse(self.path)
        try:
            body = self._read_json()
        except ValueError as exc:
            self._respond_json({"error": str(exc)}, status=413)
            return

        routes = {
            "/api/volumes/refresh": lambda: self._handle_volumes_refresh(body),
            "/api/volumes/image": lambda: self._handle_add_image(body),
            "/api/scan/start": lambda: self._handle_scan_start(body),
            "/api/scan/stop": self._handle_scan_stop,
            "/api/files/select": lambda: self._handle_select(body),
            "/api/files/select-all": lambda: self._handle_select_all(body),
            "/api/recover": lambda: self._handle_recover(body),
            "/api/recover/choose-dir": lambda: self._handle_choose_recovery_dir(body),
            "/api/recover/dismiss": lambda: self._handle_recover_dismiss(body),
        }
        handler = routes.get(parsed.path)
        if handler:
            handler()
            return
        self._respond_json({"error": "Not found"}, status=404)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        if length > MAX_JSON_BODY_BYTES:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _handle_volumes_get(self) -> None:
        with STATE.lock:
            volumes = [
                {
                    "index": index,
                    "display_name": volume.display_name,
                    "is_disk_image": volume.is_disk_image,
                    "mount_point": volume.mount_point,
                    "partitions": [
                        partition_to_dict(partition)
                        for partition in volume.partitions
                    ],
                }
                for index, volume in enumerate(STATE.volumes)
            ]
            payload = {
                "volumes": volumes,
                "include_internal": STATE.include_internal,
                "recovery_dir": STATE.recovery_dir,
                "needs_sudo": os.geteuid() != 0,
            }
        self._respond_json(payload)

    def _handle_volumes_refresh(self, body: dict[str, Any]) -> None:
        include_internal = bool(body.get("include_internal", False))
        with STATE.lock:
            STATE.include_internal = include_internal
        STATE.refresh_volumes()
        self._handle_volumes_get()

    def _handle_add_image(self, body: dict[str, Any]) -> None:
        path = str(body.get("path", "")).strip()
        if not path:
            self._respond_json({"error": "Image path is required"}, status=400)
            return
        try:
            validate_readable_file_path(path)
            volume = STATE.add_image(path)
        except SecurityError as exc:
            self._respond_json({"error": str(exc)}, status=400)
            return
        except (FileNotFoundError, ValueError, OSError) as exc:
            self._respond_json({"error": str(exc)}, status=400)
            return
        self._respond_json({"ok": True, "display_name": volume.display_name, "partitions": len(volume.partitions)})

    def _handle_scan_start(self, body: dict[str, Any]) -> None:
        with STATE.lock:
            if STATE.scanning:
                self._respond_json({"error": "Scan already running"}, status=409)
                return

        try:
            volume_index = int(body.get("volume_index", -1))
            partition_index = int(body.get("partition_index", -1))
        except (TypeError, ValueError):
            self._respond_json({"error": "Invalid volume or partition index"}, status=400)
            return

        with STATE.lock:
            if volume_index < 0 or volume_index >= len(STATE.volumes):
                self._respond_json({"error": "Select a volume first"}, status=400)
                return
            base_volume = STATE.volumes[volume_index]

        try:
            volume = volume_for_partition(base_volume, partition_index)
        except ValueError as exc:
            self._respond_json({"error": str(exc)}, status=400)
            return

        mode = str(body.get("mode", "deep"))
        categories = body.get("categories") or []
        category_set = {str(item) for item in categories} if categories else None

        if mode == "quick":
            if volume.is_disk_image:
                self._respond_json({"error": "Quick scan is not available for disk images"}, status=400)
                return
            if not volume.mount_point:
                self._respond_json(
                    {"error": "Quick scan requires a mounted volume. Use deep scan instead."},
                    status=400,
                )
                return
            with STATE.lock:
                STATE.results.clear()
                STATE.scanning = True
                STATE.progress = ScanProgress(status=ScanStatus.SCANNING)
            threading.Thread(
                target=_run_quick_scan,
                args=(volume, category_set),
                daemon=True,
            ).start()
            self._respond_json({"ok": True})
            return

        if mode == "hybrid":
            with STATE.lock:
                STATE.results.clear()
                STATE.scanning = True
                STATE.progress = ScanProgress(status=ScanStatus.SCANNING)
                STATE.scanner = HybridScanner(volume, categories=category_set)

            scanner = STATE.scanner
            assert isinstance(scanner, HybridScanner)
            scanner.start(on_file=_on_file_found, on_progress=_on_progress)
            self._respond_json({"ok": True})
            return

        with STATE.lock:
            STATE.results.clear()
            STATE.scanning = True
            STATE.progress = ScanProgress(status=ScanStatus.SCANNING)
            STATE.scanner = DeepScanner(volume, categories=category_set)

        scanner = STATE.scanner
        assert scanner is not None
        scanner.start(on_file=_on_file_found, on_progress=_on_progress)
        self._respond_json({"ok": True})

    def _handle_scan_stop(self) -> None:
        with STATE.lock:
            if STATE.scanner:
                STATE.scanner.stop()
        self._respond_json({"ok": True})

    def _handle_scan_status(self) -> None:
        with STATE.lock:
            payload = {
                "scanning": STATE.scanning,
                "progress": _progress_dict(STATE.progress),
                "recovery": _recovery_dict(STATE.recovery),
            }
        self._respond_json(payload)

    def _handle_files_get(self, query: dict[str, list[str]]) -> None:
        filt, search, extension, min_confidence = _filter_params(query)
        page = _query_int(query, "page", 0)
        page_size = _query_int(query, "page_size", DEFAULT_PAGE_SIZE)

        with STATE.lock:
            page_data = STATE.results.paginate(
                category=filt,
                search=search,
                extension=extension,
                min_confidence=min_confidence,
                page=page,
                page_size=page_size,
            )
            files = [
                STATE.file_to_dict(found, index)
                for index, found in page_data["files"]
            ]
            large_result_set = STATE.results.count() >= LARGE_RESULT_THRESHOLD

        self._respond_json(
            {
                "files": files,
                "total": page_data["total"],
                "page": page_data["page"],
                "page_size": page_data["page_size"],
                "total_pages": page_data["total_pages"],
                "showing_from": page_data["showing_from"],
                "showing_to": page_data["showing_to"],
                "large_result_set": large_result_set,
            }
        )

    def _handle_files_summary(self, query: dict[str, list[str]]) -> None:
        filt, search, extension, min_confidence = _filter_params(query)
        with STATE.lock:
            summary = STATE.results.summarize(
                category=filt,
                search=search,
                extension=extension,
                min_confidence=min_confidence,
            )
        self._respond_json(summary)

    def _handle_file_detail(self, index: int) -> None:
        detail = STATE.file_detail(index)
        if detail is None:
            self._respond_json({"error": "File not found"}, status=404)
            return
        self._respond_json(detail)

    def _handle_select(self, body: dict[str, Any]) -> None:
        indices = body.get("indices") or []
        selected = bool(body.get("selected", True))
        with STATE.lock:
            for raw in indices:
                try:
                    index = int(raw)
                except (TypeError, ValueError):
                    continue
                found = STATE.results.get(index)
                if found is not None:
                    STATE.results.set_selected([index], selected)
        self._respond_json({"ok": True})

    def _handle_select_all(self, body: dict[str, Any]) -> None:
        filt = str(body.get("filter", "all"))
        search = str(body.get("search", ""))
        extension = str(body.get("extension", "all"))
        min_confidence = str(body.get("min_confidence", DEFAULT_MIN_CONFIDENCE))
        selected = bool(body.get("selected", True))
        with STATE.lock:
            STATE.results.set_selected_matching(
                category=filt,
                search=search,
                extension=extension,
                min_confidence=min_confidence,
                selected=selected,
            )
        self._respond_json({"ok": True})

    def _handle_choose_recovery_dir(self, body: dict[str, Any]) -> None:
        initial = str(body.get("initial", "")).strip() or STATE.recovery_dir
        path = _choose_folder_macos(initial)
        if path is None:
            self._respond_json({"cancelled": True})
            return
        with STATE.lock:
            STATE.recovery_dir = path
        self._respond_json({"ok": True, "path": path})

    def _handle_recover(self, body: dict[str, Any]) -> None:
        destination = str(body.get("destination", "")).strip() or STATE.recovery_dir

        try:
            destination = validate_recovery_destination(destination)
        except SecurityError as exc:
            self._respond_json({"error": str(exc)}, status=400)
            return

        with STATE.lock:
            if STATE.recovery.status == RecoveryStatus.RUNNING:
                self._respond_json({"error": "Recovery already in progress"}, status=409)
                return
            STATE.recovery_dir = destination
            files = STATE.results.selected_files()

        if not destination:
            self._respond_json({"error": "Choose a destination folder"}, status=400)
            return
        if not files:
            self._respond_json({"error": "No files selected for recovery"}, status=400)
            return

        with STATE.lock:
            STATE.recovery = RecoveryProgress(
                status=RecoveryStatus.RUNNING,
                total=len(files),
                destination=destination,
            )

        threading.Thread(
            target=_run_recovery,
            args=(files, destination),
            daemon=True,
        ).start()
        self._respond_json({"ok": True, "count": len(files), "destination": destination})

    def _handle_recover_dismiss(self, body: dict[str, Any]) -> None:
        del body
        with STATE.lock:
            if STATE.recovery.status != RecoveryStatus.RUNNING:
                STATE.recovery = RecoveryProgress()
        self._respond_json({"ok": True})

    def _handle_preview(self, index_text: str) -> None:
        try:
            index = int(index_text)
        except ValueError:
            self._respond_json({"error": "Invalid index"}, status=400)
            return

        with STATE.lock:
            found = STATE.results.get(index)
            if found is None:
                self._respond_json({"error": "File not found"}, status=404)
                return

        preview, detail = render_preview(found)
        if preview is None or not preview.data:
            payload = {"error": "Preview unavailable"}
            if detail:
                payload["detail"] = detail
            self._respond_json(payload, status=404)
            return

        self.send_response(200)
        self.send_header("Content-Type", preview.content_type)
        self.send_header("Content-Length", str(len(preview.data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(preview.data)

    def _respond_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _query_int(query: dict[str, list[str]], key: str, default: int) -> int:
    raw = (query.get(key) or [str(default)])[0]
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _filter_params(query: dict[str, list[str]]) -> tuple[str, str, str, str]:
    category = (query.get("filter") or ["all"])[0]
    search = (query.get("search") or [""])[0]
    extension = (query.get("extension") or ["all"])[0]
    min_confidence = (query.get("min_confidence") or [DEFAULT_MIN_CONFIDENCE])[0]
    if min_confidence not in ("high", "medium", "low"):
        min_confidence = DEFAULT_MIN_CONFIDENCE
    return category, search, extension, min_confidence


def _recovery_dict(progress: RecoveryProgress) -> dict[str, Any]:
    return {
        "status": progress.status.value,
        "total": progress.total,
        "completed": progress.completed,
        "succeeded": progress.succeeded,
        "failed": progress.failed,
        "destination": progress.destination,
        "current_file": progress.current_file,
        "percent": progress.percent,
        "error": progress.error,
    }


def _progress_dict(progress: ScanProgress) -> dict[str, Any]:
    percent = progress.percent
    if not math.isfinite(percent):
        percent = 0.0
    summary = progress.progress_summary if progress.status == ScanStatus.SCANNING else f"{percent:.1f}%"
    if "nan" in summary.lower():
        summary = f"{percent:.1f}%"
    return {
        "status": progress.status.value,
        "percent": percent,
        "summary": summary,
        "message": progress.current_message,
        "files_found": progress.files_found,
        "error": progress.error,
    }


def _on_file_found(found: FoundFile) -> None:
    with STATE.lock:
        STATE.results.add(found)
        if STATE.results.count() == LARGE_RESULT_THRESHOLD:
            STATE.progress.current_message = (
                f"Large result set ({LARGE_RESULT_THRESHOLD:,}+ files). "
                "The UI uses pagination to stay responsive."
            )


def _on_progress(progress: ScanProgress) -> None:
    with STATE.lock:
        STATE.progress = progress
        if progress.status in (ScanStatus.COMPLETE, ScanStatus.ERROR):
            STATE.scanning = False


def _run_quick_scan(volume: VolumeInfo, categories: Optional[set[str]]) -> None:
    try:
        files = quick_scan_mount(volume.mount_point or "", categories=categories)
        with STATE.lock:
            STATE.results.extend(files)
            STATE.progress = ScanProgress(
                status=ScanStatus.COMPLETE,
                bytes_scanned=1,
                total_bytes=1,
                files_found=STATE.results.count(),
                current_message=f"Quick scan complete. Found {len(files)} file(s).",
            )
            STATE.scanning = False
    except OSError as exc:
        with STATE.lock:
            STATE.progress = ScanProgress(status=ScanStatus.ERROR, error=str(exc))
            STATE.scanning = False


def _choose_folder_macos(initial: Optional[str] = None) -> Optional[str]:
    """Show the native macOS folder picker. Returns None if cancelled or unavailable."""
    if not os.path.isfile("/usr/bin/osascript"):
        return None
    prompt = "Choose a folder to recover files into"
    if initial and os.path.isdir(initial):
        escaped = initial.replace("\\", "\\\\").replace('"', '\\"')
        script = (
            f'POSIX path of (choose folder with prompt "{prompt}" '
            f'default location (POSIX file "{escaped}"))'
        )
    else:
        script = f'POSIX path of (choose folder with prompt "{prompt}")'
    result = subprocess.run(
        ["osascript", "-e", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    path = result.stdout.strip()
    return path or None


def _run_recovery(files: list[FoundFile], destination: str) -> None:
    def on_progress(index: int, _total: int, result: RecoveryResult) -> None:
        with STATE.lock:
            STATE.recovery.completed = index
            if result.success:
                STATE.recovery.succeeded += 1
            else:
                STATE.recovery.failed += 1
            STATE.recovery.current_file = result.source.filename

    try:
        results = recover_files(files, destination, on_progress=on_progress)
        ok = sum(1 for result in results if result.success)
        failed = len(results) - ok
        with STATE.lock:
            STATE.recovery.status = RecoveryStatus.COMPLETE
            STATE.recovery.completed = len(files)
            STATE.recovery.succeeded = ok
            STATE.recovery.failed = failed
            STATE.recovery.current_file = ""
    except OSError as exc:
        with STATE.lock:
            STATE.recovery.status = RecoveryStatus.ERROR
            STATE.recovery.error = str(exc)
            STATE.recovery.current_file = ""


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Recovery — Mac Disk Recovery</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #111418;
      --panel: #1a1f27;
      --border: #2b3340;
      --text: #e8edf5;
      --muted: #9aa7b8;
      --accent: #4da3ff;
      --ok: #47c07a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    header h1 { margin: 0; font-size: 1.2rem; }
    .layout {
      display: grid;
      grid-template-columns: 300px minmax(0, 1fr) 360px;
      min-height: calc(100vh - 65px);
    }
    .sidebar, .main, .preview-pane { padding: 16px; }
    .sidebar, .main { border-right: 1px solid var(--border); }
    .preview-pane {
      display: flex;
      flex-direction: column;
      min-height: 0;
    }
    .preview-panel {
      position: sticky;
      top: 16px;
      display: flex;
      flex-direction: column;
      height: calc(100vh - 97px);
      min-height: 0;
    }
    .preview-panel h2 { flex-shrink: 0; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
      margin-bottom: 14px;
    }
    .panel h2 {
      margin: 0 0 12px;
      font-size: 0.95rem;
    }
    label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 6px; }
    select, input[type=text] {
      width: 100%;
      padding: 8px 10px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: #0f1318;
      color: var(--text);
      margin-bottom: 10px;
    }
    .row { display: flex; gap: 8px; flex-wrap: wrap; }
    button {
      border: 1px solid var(--border);
      background: #222833;
      color: var(--text);
      border-radius: 8px;
      padding: 8px 12px;
      cursor: pointer;
    }
    button.primary { background: var(--accent); border-color: var(--accent); color: #041018; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .checks label { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; color: var(--text); }
    .progress-bar {
      height: 10px;
      background: #0f1318;
      border-radius: 999px;
      overflow: hidden;
      margin: 10px 0;
    }
    .progress-bar > div {
      height: 100%;
      width: 0;
      background: linear-gradient(90deg, #358ee6, #47c07a);
      transition: width 0.2s ease;
    }
    .status { color: var(--muted); font-size: 0.9rem; min-height: 1.2em; }
    .banner {
      background: #2a2208;
      border: 1px solid #6b5718;
      color: #f6df95;
      padding: 10px 12px;
      border-radius: 8px;
      margin-bottom: 12px;
      font-size: 0.9rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }
    th, td {
      text-align: left;
      padding: 8px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    tr.selected-row { background: rgba(77, 163, 255, 0.08); }
    tr.preview-row { background: rgba(71, 192, 122, 0.08); }
    .preview-box {
      flex: 1;
      min-height: 200px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0f1318;
      border: 1px dashed var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .preview-box img {
      max-width: 100%;
      max-height: 100%;
      object-fit: contain;
    }
    .preview-meta {
      white-space: pre-wrap;
      color: var(--muted);
      font-size: 0.85rem;
      margin-top: 10px;
      flex-shrink: 0;
      max-height: 180px;
      overflow: auto;
    }
    .files-table-wrap {
      overflow: auto;
      max-height: calc(100vh - 340px);
      margin-top: 10px;
    }
    .message { color: var(--ok); min-height: 1.2em; margin-top: 8px; }
    .summary-bar {
      color: var(--muted);
      font-size: 0.88rem;
      margin: 8px 0;
      line-height: 1.5;
    }
    .summary-bar strong { color: var(--text); }
    .pager {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      margin-top: 10px;
    }
    .pager input[type="search"], .pager select {
      width: auto;
      margin-bottom: 0;
    }
    .notice {
      background: #142033;
      border: 1px solid #2d5a87;
      color: #b9d7f5;
      padding: 10px 12px;
      border-radius: 8px;
      margin: 8px 0 0;
      font-size: 0.88rem;
    }
    .modal[hidden] { display: none; }
    .modal {
      position: fixed;
      inset: 0;
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .modal-backdrop {
      position: absolute;
      inset: 0;
      background: rgba(0, 0, 0, 0.55);
    }
    .modal-dialog {
      position: relative;
      width: min(480px, 100%);
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 16px 48px rgba(0, 0, 0, 0.35);
    }
    .modal-dialog h2 {
      margin: 0 0 8px;
      font-size: 1.1rem;
    }
    .modal-dialog p {
      margin: 0 0 12px;
      color: var(--muted);
      line-height: 1.5;
    }
    .modal-detail {
      color: var(--text);
      font-size: 0.9rem;
      margin: 10px 0 16px;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .modal-actions {
      display: flex;
      justify-content: flex-end;
      margin-top: 16px;
    }
    @media (max-width: 1200px) {
      .layout {
        grid-template-columns: 280px minmax(0, 1fr);
      }
      .preview-pane {
        grid-column: 1 / -1;
        border-right: none;
        border-top: 1px solid var(--border);
      }
      .preview-panel {
        position: static;
        height: auto;
      }
      .preview-box {
        min-height: 240px;
        max-height: 360px;
      }
      .files-table-wrap {
        max-height: 420px;
      }
    }
  </style>
</head>
<body>
  <header>
    <h1>Recovery — Mac Disk Recovery</h1>
    <div id="top-message" class="message"></div>
  </header>
  <div class="layout">
    <aside class="sidebar">
      <div id="sudo-banner" class="banner" hidden>
        Deep scans of raw disks require administrator access. Restart with:
        <code>sudo ./recovery.sh</code>
      </div>
      <section class="panel">
        <h2>Attached Volumes</h2>
        <label for="volume-select">Volume</label>
        <select id="volume-select" size="8"></select>
        <label for="partition-select" style="margin-top:12px;">Scan region</label>
        <select id="partition-select" disabled>
          <option value="-1">Whole disk</option>
        </select>
        <div class="row">
          <button id="refresh-volumes">Refresh</button>
          <label style="display:flex;align-items:center;gap:6px;margin:0;">
            <input type="checkbox" id="include-internal"> Internal disks
          </label>
        </div>
        <label for="image-path" style="margin-top:12px;">Disk image path</label>
        <input id="image-path" type="text" placeholder="/Users/you/disk.img">
        <button id="load-image">Load Image</button>
      </section>
      <section class="panel">
        <h2>Scan Options</h2>
        <label><input type="radio" name="mode" value="deep" checked> Deep scan (file carving)</label>
        <label><input type="radio" name="mode" value="hybrid"> Hybrid (filesystem + unallocated carve)</label>
        <label><input type="radio" name="mode" value="quick"> Quick scan (mounted files only)</label>
        <div class="checks" style="margin-top:10px;">
          <label><input type="checkbox" class="cat" value="image" checked> Images</label>
          <label><input type="checkbox" class="cat" value="video" checked> Videos</label>
          <label><input type="checkbox" class="cat" value="document" checked> Documents</label>
          <label><input type="checkbox" class="cat" value="archive" checked> Archives</label>
          <label><input type="checkbox" class="cat" value="other" checked> Other</label>
        </div>
        <div class="row" style="margin-top:12px;">
          <button id="start-scan" class="primary" disabled>Start Scan</button>
          <button id="stop-scan" disabled>Stop</button>
        </div>
      </section>
      <section class="panel">
        <h2>Recover To</h2>
        <div id="recovery-size" class="summary-bar">Selected: 0 files · 0 B</div>
        <label for="recovery-dir">Destination folder</label>
        <div class="row">
          <input id="recovery-dir" type="text" placeholder="Choose a folder…" style="flex:1;">
          <button id="choose-recovery-dir" type="button">Choose…</button>
        </div>
        <div class="row" style="margin-top:12px;">
          <button id="recover-selected" class="primary">Recover Selected</button>
        </div>
      </section>
    </aside>
    <main class="main">
      <section class="panel">
        <h2>Progress</h2>
        <div class="status" id="status-text">Select a volume and start a scan.</div>
        <div class="progress-bar"><div id="progress-fill"></div></div>
        <div class="status" id="progress-text">0%</div>
      </section>
      <section class="panel">
        <div class="row" style="justify-content:space-between; align-items:center;">
          <h2 style="margin:0;">Found Files</h2>
          <div class="row">
            <label style="margin:0;">Category</label>
            <select id="filter">
              <option value="all">All</option>
              <option value="image">Images</option>
              <option value="video">Videos</option>
              <option value="document">Documents</option>
              <option value="archive">Archives</option>
              <option value="other">Other</option>
            </select>
            <label style="margin:0;">Extension</label>
            <select id="extension-filter">
              <option value="all">All types</option>
            </select>
            <label style="margin:0;">Confidence</label>
            <select id="confidence-filter">
              <option value="medium" selected>Medium+</option>
              <option value="high">High only</option>
              <option value="low">All</option>
            </select>
            <button id="select-all">Select Filtered</button>
            <button id="select-none">Clear Filtered</button>
          </div>
        </div>
        <div id="files-summary" class="summary-bar">No files yet.</div>
        <div id="large-set-notice" class="notice" hidden>
          Large result set detected. Only a page of files is loaded in the browser at a time to keep the UI responsive.
          Use search and filters to narrow results, then recover only checked files.
        </div>
        <div class="files-table-wrap">
          <table>
            <thead>
              <tr>
                <th></th><th>Filename</th><th>Type</th><th>Size</th><th>Created</th><th>Confidence</th><th>Offset / Path</th>
              </tr>
            </thead>
            <tbody id="files-body"></tbody>
          </table>
        </div>
        <div class="pager">
          <button id="page-prev">Previous</button>
          <span id="page-label">Page 1 of 1</span>
          <button id="page-next">Next</button>
          <label>Rows</label>
          <select id="page-size">
            <option value="50">50</option>
            <option value="100" selected>100</option>
            <option value="200">200</option>
          </select>
          <input id="file-search" type="search" placeholder="Search filename or offset">
        </div>
      </section>
    </main>
    <aside class="preview-pane">
      <section class="panel preview-panel">
        <h2>Preview</h2>
        <div class="preview-box" id="preview-box">Select a file to preview</div>
        <div class="preview-meta" id="preview-meta"></div>
      </section>
    </aside>
  </div>
  <div id="recovery-modal" class="modal" hidden>
    <div class="modal-backdrop"></div>
    <div class="modal-dialog" role="dialog" aria-labelledby="recovery-modal-title" aria-modal="true">
      <h2 id="recovery-modal-title">Recovering Files</h2>
      <p id="recovery-modal-text"></p>
      <div class="progress-bar"><div id="recovery-modal-fill"></div></div>
      <div id="recovery-modal-detail" class="modal-detail"></div>
      <div class="modal-actions">
        <button id="recovery-modal-close" class="primary" hidden>Close</button>
      </div>
    </div>
  </div>
  <script>
    const els = {
      volumeSelect: document.getElementById("volume-select"),
      partitionSelect: document.getElementById("partition-select"),
      includeInternal: document.getElementById("include-internal"),
      imagePath: document.getElementById("image-path"),
      loadImage: document.getElementById("load-image"),
      refreshVolumes: document.getElementById("refresh-volumes"),
      startScan: document.getElementById("start-scan"),
      stopScan: document.getElementById("stop-scan"),
      statusText: document.getElementById("status-text"),
      progressFill: document.getElementById("progress-fill"),
      progressText: document.getElementById("progress-text"),
      filesBody: document.getElementById("files-body"),
      filesSummary: document.getElementById("files-summary"),
      largeSetNotice: document.getElementById("large-set-notice"),
      filter: document.getElementById("filter"),
      extensionFilter: document.getElementById("extension-filter"),
      confidenceFilter: document.getElementById("confidence-filter"),
      fileSearch: document.getElementById("file-search"),
      pagePrev: document.getElementById("page-prev"),
      pageNext: document.getElementById("page-next"),
      pageLabel: document.getElementById("page-label"),
      pageSize: document.getElementById("page-size"),
      selectAll: document.getElementById("select-all"),
      selectNone: document.getElementById("select-none"),
      recoveryDir: document.getElementById("recovery-dir"),
      recoverySize: document.getElementById("recovery-size"),
      chooseRecoveryDir: document.getElementById("choose-recovery-dir"),
      recoverSelected: document.getElementById("recover-selected"),
      recoveryModal: document.getElementById("recovery-modal"),
      recoveryModalTitle: document.getElementById("recovery-modal-title"),
      recoveryModalText: document.getElementById("recovery-modal-text"),
      recoveryModalFill: document.getElementById("recovery-modal-fill"),
      recoveryModalDetail: document.getElementById("recovery-modal-detail"),
      recoveryModalClose: document.getElementById("recovery-modal-close"),
      previewBox: document.getElementById("preview-box"),
      previewMeta: document.getElementById("preview-meta"),
      sudoBanner: document.getElementById("sudo-banner"),
      topMessage: document.getElementById("top-message"),
    };

    let scanning = false;
    let volumeData = [];
    let previewIndex = null;
    let previewObjectUrl = null;
    let previewRequestId = 0;
    let previewAbortController = null;
    let lastFilesFound = -1;
    let currentPage = 0;
    let totalPages = 1;
    let refreshTimer = null;
    let searchTimer = null;
    const REFRESH_INTERVAL_MS = 2500;
    let recoveryModalOpen = false;
    let recoveryModalDismissed = false;

    function openRecoveryModal(total, destination) {
      recoveryModalDismissed = false;
      recoveryModalOpen = true;
      els.recoveryModal.hidden = false;
      els.recoveryModalTitle.textContent = "Recovering Files";
      els.recoveryModalText.textContent =
        `Recovering ${total.toLocaleString()} file(s) to ${destination}`;
      els.recoveryModalDetail.textContent = "Starting…";
      els.recoveryModalFill.style.width = "0%";
      els.recoveryModalClose.hidden = true;
      els.recoverSelected.disabled = true;
    }

    async function closeRecoveryModal() {
      recoveryModalOpen = false;
      recoveryModalDismissed = true;
      els.recoveryModal.hidden = true;
      try {
        await api("/api/recover/dismiss", { method: "POST", body: "{}" });
      } catch (_error) {
        // Ignore dismiss errors; modal is already closed locally.
      }
    }

    function updateRecoveryModal(recovery) {
      if (!recovery || recovery.status === "idle") return;
      if (recoveryModalDismissed) return;

      const percent = Number.isFinite(recovery.percent) ? recovery.percent : 0;
      if (recoveryModalOpen) {
        els.recoveryModalFill.style.width = `${percent}%`;
      }

      if (recovery.status === "running") {
        if (!recoveryModalOpen) {
          openRecoveryModal(recovery.total, recovery.destination);
        }
        els.recoveryModalTitle.textContent = "Recovering Files";
        els.recoveryModalText.textContent =
          `Recovering ${recovery.total.toLocaleString()} file(s) to ${recovery.destination}`;
        const parts = [
          `${recovery.completed.toLocaleString()} of ${recovery.total.toLocaleString()} processed`,
          `${recovery.succeeded.toLocaleString()} succeeded`,
        ];
        if (recovery.failed > 0) {
          parts.push(`${recovery.failed.toLocaleString()} failed`);
        }
        let detail = parts.join(" · ");
        if (recovery.current_file) {
          detail += `\nCurrent: ${recovery.current_file}`;
        }
        els.recoveryModalDetail.textContent = detail;
        els.recoveryModalClose.hidden = true;
        els.recoverSelected.disabled = true;
        return;
      }

      if (recovery.status === "complete") {
        els.recoveryModalTitle.textContent = "Recovery Complete";
        els.recoveryModalText.textContent =
          `Successfully recovered ${recovery.succeeded.toLocaleString()} file(s).`;
        if (recovery.failed > 0) {
          els.recoveryModalText.textContent +=
            ` ${recovery.failed.toLocaleString()} file(s) could not be recovered.`;
        }
        els.recoveryModalDetail.textContent = recovery.destination
          ? `Saved to ${recovery.destination}`
          : "";
        els.recoveryModalFill.style.width = "100%";
        els.recoveryModalClose.hidden = false;
        els.recoverSelected.disabled = false;
        return;
      }

      if (recovery.status === "error") {
        els.recoveryModalTitle.textContent = "Recovery Failed";
        els.recoveryModalText.textContent = recovery.error || "An error occurred during recovery.";
        els.recoveryModalDetail.textContent = recovery.destination
          ? `Destination: ${recovery.destination}`
          : "";
        els.recoveryModalClose.hidden = false;
        els.recoverSelected.disabled = false;
      }
    }

    function updateRecoveryControls(recovery) {
      els.recoverSelected.disabled = recovery && recovery.status === "running";
    }

    async function api(path, options = {}) {
      const response = await fetch(path, {
        headers: { "Content-Type": "application/json" },
        ...options,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || response.statusText);
      return data;
    }

    function selectedCategories() {
      return [...document.querySelectorAll(".cat:checked")].map(el => el.value);
    }

    function scanMode() {
      return document.querySelector('input[name="mode"]:checked').value;
    }

    function hasVolumeSelected() {
      return els.volumeSelect.value !== "";
    }

    function updatePartitionSelect() {
      const selected = els.volumeSelect.value;
      els.partitionSelect.innerHTML = "";
      const whole = document.createElement("option");
      whole.value = "-1";
      whole.textContent = "Whole disk";
      els.partitionSelect.appendChild(whole);

      const volume = volumeData.find(item => String(item.index) === selected);
      if (!volume || !volume.partitions || volume.partitions.length === 0) {
        els.partitionSelect.disabled = true;
        els.partitionSelect.value = "-1";
        return;
      }

      els.partitionSelect.disabled = false;
      for (const partition of volume.partitions) {
        const option = document.createElement("option");
        option.value = partition.index;
        option.textContent = partition.display_label;
        els.partitionSelect.appendChild(option);
      }
    }

    function updateScanControls() {
      els.startScan.disabled = scanning || !hasVolumeSelected();
      els.stopScan.disabled = !scanning;
    }

    async function loadVolumes() {
      const data = await api("/api/volumes");
      volumeData = data.volumes || [];
      const previous = els.volumeSelect.value;
      els.volumeSelect.innerHTML = "";
      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = "Select a volume…";
      els.volumeSelect.appendChild(placeholder);
      data.volumes.forEach(v => {
        const option = document.createElement("option");
        option.value = v.index;
        option.textContent = v.display_name;
        els.volumeSelect.appendChild(option);
      });
      const values = [...els.volumeSelect.options].map(option => option.value);
      els.volumeSelect.value = values.includes(previous) ? previous : "";
      els.recoveryDir.value = data.recovery_dir;
      els.includeInternal.checked = data.include_internal;
      els.sudoBanner.hidden = !data.needs_sudo;
      updatePartitionSelect();
      updateScanControls();
    }

    function filesQuery() {
      const params = new URLSearchParams({
        filter: els.filter.value,
        extension: els.extensionFilter.value,
        min_confidence: els.confidenceFilter.value,
        page: String(currentPage),
        page_size: els.pageSize.value,
      });
      const search = els.fileSearch.value.trim();
      if (search) params.set("search", search);
      return params.toString();
    }

    function updateExtensionOptions(extensions) {
      const current = els.extensionFilter.value;
      els.extensionFilter.innerHTML = '<option value="all">All types</option>';
      for (const item of extensions) {
        const option = document.createElement("option");
        option.value = item.ext;
        option.textContent = `.${item.ext} (${(Number(item.count) || 0).toLocaleString()})`;
        els.extensionFilter.appendChild(option);
      }
      const values = [...els.extensionFilter.options].map(option => option.value);
      els.extensionFilter.value = values.includes(current) ? current : "all";
    }

    async function refreshSummary() {
      const params = new URLSearchParams({
        filter: els.filter.value,
        extension: els.extensionFilter.value,
        min_confidence: els.confidenceFilter.value,
      });
      const search = els.fileSearch.value.trim();
      if (search) params.set("search", search);
      const data = await api(`/api/files/summary?${params.toString()}`);
      updateExtensionOptions(data.extensions || []);
      const filteredTotal = Number(data.filtered_total) || 0;
      const visibleTotal = Number(data.visible_total) || filteredTotal;
      const selectedAll = Number(data.selected_all) || 0;
      const total = Number(data.total) || 0;
      const selectedSize = data.selected_size_human || "0 B";
      const filteredSize = data.filtered_size_human || "0 B";
      const hiddenCount = Math.max(0, total - visibleTotal);
      els.filesSummary.innerHTML =
        `<strong>${filteredTotal.toLocaleString()}</strong> matching · ` +
        `<strong>${selectedAll.toLocaleString()}</strong> selected · ` +
        `<strong>${selectedSize}</strong> to recover · ` +
        `<strong>${total.toLocaleString()}</strong> total found` +
        (hiddenCount
          ? ` · <strong>${hiddenCount.toLocaleString()}</strong> hidden by confidence filter`
          : "");
      els.recoverySize.textContent =
        `Selected: ${selectedAll.toLocaleString()} file(s) · ${selectedSize}` +
        (filteredTotal !== total
          ? ` · Filtered list: ${filteredTotal.toLocaleString()} file(s) · ${filteredSize}`
          : "");
      els.largeSetNotice.hidden = !data.large_result_set;
      return data;
    }

    async function refreshFiles(options = {}) {
      const { resetPage = false } = options;
      if (resetPage) currentPage = 0;

      const data = await api(`/api/files?${filesQuery()}`);
      totalPages = Math.max(1, data.total_pages || 1);
      currentPage = Math.min(currentPage, totalPages - 1);

      els.filesBody.innerHTML = "";
      if (!data.files.length) {
        const row = document.createElement("tr");
        row.innerHTML = `<td colspan="7">No files match the current filter.</td>`;
        els.filesBody.appendChild(row);
      }

      data.files.forEach(file => {
        const row = document.createElement("tr");
        if (file.selected) row.classList.add("selected-row");
        if (previewIndex === file.index) row.classList.add("preview-row");
        row.innerHTML = `
          <td><input type="checkbox" data-index="${file.index}" ${file.selected ? "checked" : ""}></td>
          <td>${file.filename}</td>
          <td>${file.category} (.${file.extension})</td>
          <td>${file.size_human}</td>
          <td title="${file.timestamp_source === "modified" ? "No creation date found; showing last modified" : ""}">${file.timestamp}</td>
          <td>${file.confidence}</td>
          <td>${file.offset_display}</td>`;
        row.dataset.index = String(file.index);
        row.addEventListener("click", (event) => {
          if (event.target.tagName === "INPUT") return;
          showPreview(file);
        });
        els.filesBody.appendChild(row);
      });

      els.filesBody.querySelectorAll("input[type=checkbox]").forEach(box => {
        box.addEventListener("change", async () => {
          await api("/api/files/select", {
            method: "POST",
            body: JSON.stringify({
              indices: [Number(box.dataset.index)],
              selected: box.checked,
            }),
          });
          const row = box.closest("tr");
          if (row) row.classList.toggle("selected-row", box.checked);
          await refreshSummary();
        });
      });

      els.pageLabel.textContent = data.total
        ? `Page ${currentPage + 1} of ${totalPages} · showing ${data.showing_from}-${data.showing_to}`
        : "Page 1 of 1";
      els.pagePrev.disabled = currentPage <= 0;
      els.pageNext.disabled = currentPage >= totalPages - 1;
      await refreshSummary();
    }

    function scheduleRefreshFiles(force = false) {
      if (refreshTimer) {
        clearTimeout(refreshTimer);
        refreshTimer = null;
      }
      if (force || !scanning) {
        refreshFiles();
        return;
      }
      refreshTimer = setTimeout(() => {
        refreshTimer = null;
        refreshFiles();
      }, REFRESH_INTERVAL_MS);
    }

    async function showPreview(file) {
      const requestId = ++previewRequestId;
      previewIndex = file.index;
      highlightPreviewRows();

      if (previewAbortController) {
        previewAbortController.abort();
      }
      previewAbortController = new AbortController();

      try {
        const detail = await api(`/api/files/${file.index}`);
        if (requestId !== previewRequestId) return;
        els.previewMeta.textContent = detail.description;
      } catch (_error) {
        if (requestId !== previewRequestId) return;
        els.previewMeta.textContent = file.filename;
      }

      if (!file.can_preview) {
        clearPreviewObjectUrl();
        els.previewBox.textContent = "Preview not available for this file type";
        return;
      }

      els.previewBox.textContent = "Loading preview…";
      clearPreviewObjectUrl();
      try {
        const response = await fetch(`/api/preview/${file.index}?t=${Date.now()}`, {
          signal: previewAbortController.signal,
        });
        if (requestId !== previewRequestId) return;

        const contentType = response.headers.get("Content-Type") || "";
        if (!response.ok) {
          if (contentType.includes("application/json")) {
            const err = await response.json().catch(() => ({}));
            els.previewBox.textContent = err.detail || err.error || "Could not load preview";
          } else {
            els.previewBox.textContent = "Could not load preview";
          }
          return;
        }

        if (!contentType.startsWith("image/")) {
          els.previewBox.textContent = "Preview response was not a valid image";
          return;
        }

        const blob = await response.blob();
        if (requestId !== previewRequestId) return;
        if (!blob.size) {
          els.previewBox.textContent = "Preview data is empty";
          return;
        }

        const header = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
        const isPng = header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4E && header[3] === 0x47;
        const isJpeg = header[0] === 0xFF && header[1] === 0xD8;
        if (!isPng && !isJpeg) {
          els.previewBox.textContent = "Preview data is not a decodable image";
          return;
        }

        previewObjectUrl = URL.createObjectURL(blob);
        const img = document.createElement("img");
        img.alt = "preview";
        img.onload = () => {
          if (requestId !== previewRequestId) return;
          els.previewBox.innerHTML = "";
          els.previewBox.appendChild(img);
        };
        img.onerror = () => {
          if (requestId !== previewRequestId) return;
          clearPreviewObjectUrl();
          els.previewBox.textContent = "Browser could not render this image (likely corrupt)";
        };
        img.src = previewObjectUrl;
      } catch (error) {
        if (requestId !== previewRequestId) return;
        if (error.name === "AbortError") return;
        els.previewBox.textContent = "Could not load preview";
      }
    }

    function clearPreviewObjectUrl() {
      if (previewObjectUrl) {
        URL.revokeObjectURL(previewObjectUrl);
        previewObjectUrl = null;
      }
    }

    function highlightPreviewRows() {
      els.filesBody.querySelectorAll("tr").forEach(row => {
        row.classList.toggle("preview-row", row.dataset.index === String(previewIndex));
      });
    }

    let wasScanning = false;

    async function pollStatus() {
      try {
        const response = await fetch("/api/scan/status");
        const data = await response.json();
        scanning = data.scanning;
        updateScanControls();
        const percent = Number.isFinite(data.progress.percent) ? data.progress.percent : 0;
        els.progressFill.style.width = `${percent}%`;
        const summary = data.progress.summary || "0%";
        els.progressText.textContent = summary.toLowerCase().includes("nan") ? `${percent.toFixed(1)}%` : summary;
        els.statusText.textContent = data.progress.message || data.progress.status;
        if (data.progress.error) {
          els.statusText.textContent = data.progress.error;
        }
        updateRecoveryModal(data.recovery);
        updateRecoveryControls(data.recovery);
        const filesFound = data.progress.files_found ?? 0;
        if (filesFound !== lastFilesFound) {
          lastFilesFound = filesFound;
          if (scanning) {
            await refreshSummary();
            scheduleRefreshFiles(false);
          } else {
            scheduleRefreshFiles(true);
          }
        }
        if (wasScanning && !scanning) {
          scheduleRefreshFiles(true);
        }
        wasScanning = scanning;
      } catch (error) {
        console.error(error);
      }
    }

    els.refreshVolumes.addEventListener("click", async () => {
      await api("/api/volumes/refresh", {
        method: "POST",
        body: JSON.stringify({ include_internal: els.includeInternal.checked }),
      });
      await loadVolumes();
    });

    els.includeInternal.addEventListener("change", () => els.refreshVolumes.click());

    els.volumeSelect.addEventListener("change", () => {
      updatePartitionSelect();
      updateScanControls();
    });

    els.chooseRecoveryDir.addEventListener("click", async () => {
      try {
        const data = await api("/api/recover/choose-dir", {
          method: "POST",
          body: JSON.stringify({ initial: els.recoveryDir.value.trim() }),
        });
        if (data.cancelled) return;
        els.recoveryDir.value = data.path;
      } catch (error) {
        alert(error.message);
      }
    });

    els.loadImage.addEventListener("click", async () => {
      try {
        await api("/api/volumes/image", {
          method: "POST",
          body: JSON.stringify({ path: els.imagePath.value }),
        });
        await loadVolumes();
        els.volumeSelect.value = "0";
        updatePartitionSelect();
        updateScanControls();
        document.querySelector('input[name="mode"][value="deep"]').checked = true;
        els.topMessage.textContent = "Disk image loaded. Select it and start a deep scan.";
      } catch (error) {
        alert(error.message);
      }
    });

    els.startScan.addEventListener("click", async () => {
      if (!hasVolumeSelected()) {
        alert("Select a volume to scan first.");
        return;
      }
      try {
        previewIndex = null;
        clearPreviewObjectUrl();
        els.previewBox.textContent = "Select a file to preview";
        els.previewMeta.textContent = "";
        await api("/api/scan/start", {
          method: "POST",
          body: JSON.stringify({
            volume_index: Number(els.volumeSelect.value),
            partition_index: Number(els.partitionSelect.value),
            mode: scanMode(),
            categories: selectedCategories(),
          }),
        });
        scanning = true;
        lastFilesFound = -1;
        currentPage = 0;
        updateScanControls();
      } catch (error) {
        alert(error.message);
      }
    });

    els.stopScan.addEventListener("click", async () => {
      await api("/api/scan/stop", { method: "POST", body: "{}" });
    });

    els.filter.addEventListener("change", () => refreshFiles({ resetPage: true }));
    els.extensionFilter.addEventListener("change", () => refreshFiles({ resetPage: true }));
    els.confidenceFilter.addEventListener("change", () => refreshFiles({ resetPage: true }));

    els.pageSize.addEventListener("change", () => refreshFiles({ resetPage: true }));
    els.pagePrev.addEventListener("click", () => {
      if (currentPage > 0) {
        currentPage -= 1;
        refreshFiles();
      }
    });
    els.pageNext.addEventListener("click", () => {
      if (currentPage < totalPages - 1) {
        currentPage += 1;
        refreshFiles();
      }
    });
    els.fileSearch.addEventListener("input", () => {
      if (searchTimer) clearTimeout(searchTimer);
      searchTimer = setTimeout(() => refreshFiles({ resetPage: true }), 300);
    });

    els.selectAll.addEventListener("click", async () => {
      const summary = await refreshSummary();
      if (summary.filtered_total > 1000) {
        const ok = confirm(
          `Select all ${summary.filtered_total.toLocaleString()} matching files? ` +
          "Recovering very large selections can take a long time."
        );
        if (!ok) return;
      }
      await api("/api/files/select-all", {
        method: "POST",
        body: JSON.stringify({
          filter: els.filter.value,
          extension: els.extensionFilter.value,
          min_confidence: els.confidenceFilter.value,
          search: els.fileSearch.value.trim(),
          selected: true,
        }),
      });
      refreshFiles();
    });

    els.selectNone.addEventListener("click", async () => {
      await api("/api/files/select-all", {
        method: "POST",
        body: JSON.stringify({
          filter: els.filter.value,
          extension: els.extensionFilter.value,
          min_confidence: els.confidenceFilter.value,
          search: els.fileSearch.value.trim(),
          selected: false,
        }),
      });
      refreshFiles();
    });

    async function syncVisibleSelections() {
      const boxes = [...els.filesBody.querySelectorAll("input[type=checkbox]")];
      await Promise.all(
        boxes.map(box =>
          api("/api/files/select", {
            method: "POST",
            body: JSON.stringify({
              indices: [Number(box.dataset.index)],
              selected: box.checked,
            }),
          })
        )
      );
    }

    async function recoverSelected() {
      try {
        const destination = els.recoveryDir.value.trim();
        if (!destination) {
          alert("Choose a destination folder first.");
          return;
        }
        await syncVisibleSelections();
        const summary = await refreshSummary();
        const count = Number(summary.selected_all) || 0;
        const size = summary.selected_size_human || "0 B";
        if (count <= 0) {
          alert("No files selected for recovery.");
          return;
        }
        if (count > 500) {
          const ok = confirm(
            `Recover ${count.toLocaleString()} selected file(s) (${size})? ` +
            "This may take a long time and use significant disk space."
          );
          if (!ok) return;
        }
        const data = await api("/api/recover", {
          method: "POST",
          body: JSON.stringify({ destination }),
        });
        openRecoveryModal(data.count, data.destination || destination);
      } catch (error) {
        alert(error.message);
      }
    }

    els.recoverSelected.addEventListener("click", recoverSelected);

    els.recoveryModalClose.addEventListener("click", closeRecoveryModal);

    loadVolumes().then(async () => {
      await refreshFiles();
      lastFilesFound = 0;
    });
    setInterval(pollStatus, 1000);
  </script>
</body>
</html>
"""
