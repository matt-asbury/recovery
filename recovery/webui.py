from __future__ import annotations

import json
import math
import os
import subprocess
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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
from recovery.encryption import encryption_to_dict, scan_mode_error
from recovery.partitions import partition_to_dict
from recovery.volumes import list_volumes, volume_for_partition, volume_from_image

DEFAULT_PORT = 8765
DEFAULT_DEST = os.path.expanduser("~/RecoveredFiles")
STATIC_DIR = Path(__file__).resolve().parent / "static"
_STATIC_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
}


def _load_index_html() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


INDEX_HTML = _load_index_html()


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
        if parsed.path.startswith("/static/"):
            self._serve_static(parsed.path[len("/static/") :])
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
                    "encryption": encryption_to_dict(volume.encryption),
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

        scan_error = scan_mode_error(volume, mode)
        if scan_error:
            self._respond_json({"error": scan_error}, status=400)
            return

        if mode == "quick":
            if volume.is_disk_image:
                self._respond_json({"error": "Quick scan is not available for disk images"}, status=400)
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

    def _serve_static(self, relative_path: str) -> None:
        if not relative_path or ".." in relative_path or relative_path.startswith("/"):
            self._respond_json({"error": "Forbidden"}, status=403)
            return
        file_path = (STATIC_DIR / relative_path).resolve()
        if not str(file_path).startswith(str(STATIC_DIR.resolve())):
            self._respond_json({"error": "Forbidden"}, status=403)
            return
        if not file_path.is_file():
            self._respond_json({"error": "Not found"}, status=404)
            return
        suffix = file_path.suffix.lower()
        content_type = _STATIC_MIME.get(suffix, "application/octet-stream")
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)


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


