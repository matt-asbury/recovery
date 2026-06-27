import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from recovery.webui import RecoveryHandler


def _start_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), RecoveryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def _get_json(url: str) -> tuple[int, dict]:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_index_and_static_assets() -> None:
    server, base = _start_server()
    try:
        with urllib.request.urlopen(f"{base}/", timeout=5) as response:
            html = response.read().decode("utf-8")
            assert response.status == 200
            assert "Recovery" in html
            assert "/static/app.css" in html
        with urllib.request.urlopen(f"{base}/static/app.css", timeout=5) as response:
            css = response.read().decode("utf-8")
            assert response.status == 200
            assert ".app-header" in css
    finally:
        server.shutdown()


def test_volumes_endpoint_returns_json() -> None:
    server, base = _start_server()
    try:
        status, payload = _get_json(f"{base}/api/volumes")
        assert status == 200
        assert "volumes" in payload
        assert "needs_sudo" in payload
    finally:
        server.shutdown()


def test_scan_status_endpoint() -> None:
    server, base = _start_server()
    try:
        status, payload = _get_json(f"{base}/api/scan/status")
        assert status == 200
        assert "scanning" in payload
        assert "recovery" in payload
        assert "log" in payload
        assert isinstance(payload["log"], list)
        assert "bytes_scanned_human" in payload["progress"]
        assert "transfer_rate_human" in payload["progress"]
    finally:
        server.shutdown()


def test_recover_requires_destination() -> None:
    server, base = _start_server()
    try:
        request = urllib.request.Request(
            f"{base}/api/recover",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 400
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
    finally:
        server.shutdown()


def test_load_disk_image_validates_path() -> None:
    server, base = _start_server()
    try:
        request = urllib.request.Request(
            f"{base}/api/volumes/image",
            data=json.dumps({"path": "/definitely/missing.img"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(request, timeout=5)
        assert excinfo.value.code == 400
    finally:
        server.shutdown()


def _minimal_valid_jpeg() -> bytes:
    """Build a small JPEG that passes structure and entropy validation."""
    data = b"\xff\xd8"
    jfif = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    data += b"\xff\xe0" + (len(jfif) + 2).to_bytes(2, "big") + jfif
    sof = b"\x08\x00\x10\x00\x10\x01\x01\x00\x00"
    data += b"\xff\xc0" + (len(sof) + 2).to_bytes(2, "big") + sof
    data += bytes((index * 7 + 13) % 256 for index in range(900))
    data += b"\xff\xd9"
    return data


def test_scan_finds_jpeg_in_disk_image() -> None:
    jpeg = _minimal_valid_jpeg()
    padding = b"\x00" * 8192

    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as handle:
        handle.write(padding + jpeg + padding)
        image_path = handle.name

    try:
        from recovery.scanner import DeepScanner
        from recovery.volumes import volume_from_image

        volume = volume_from_image(image_path)
        scanner = DeepScanner(volume)
        found: list = []
        scanner.start(on_file=found.append)
        scanner.join()
        assert scanner.progress.status.value in {"complete", "error"}
        assert len(found) >= 1
    finally:
        os.unlink(image_path)
