from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from recovery.models import FileCategory, FoundFile
from recovery.device_io import read_bytes
from recovery.timestamps import format_timestamp

PREVIEWABLE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff"}
MAX_PREVIEW_BYTES = 4 * 1024 * 1024
PREVIEW_MAX_DIMENSION = 480
MIN_PREVIEW_BYTES = 128
MAX_NULL_RATIO = 0.92
MAX_IMAGE_DIMENSION = 50000
MIN_ENTROPY_UNIQUE_BYTES = 12


@dataclass(frozen=True)
class PreviewResult:
    data: bytes
    content_type: str


def can_preview(found: FoundFile) -> bool:
    return (
        found.category == FileCategory.IMAGE
        and found.extension.lower() in PREVIEWABLE_EXTENSIONS
    )


def preview_description(found: FoundFile) -> str:
    lines = [
        found.filename,
        f"Type: {found.signature_name} ({found.category_label})",
        f"Size: {found.size_human}",
        f"Created: {format_timestamp(found.created_at)}",
        f"Confidence: {found.confidence}",
    ]
    if found.modified_at is not None and found.modified_at != found.created_at:
        lines.insert(4, f"Modified: {format_timestamp(found.modified_at)}")
    elif found.created_at is None and found.modified_at is not None:
        lines[3] = f"Modified: {format_timestamp(found.modified_at)} (no creation date found)"
    if found.preview_note:
        lines.append(f"Path: {found.preview_note}")
    else:
        lines.append(f"Offset: 0x{found.offset:x}")
    return "\n".join(lines)


def render_preview(found: FoundFile) -> tuple[Optional[PreviewResult], Optional[str]]:
    """Return PNG preview bytes validated as decodable image data."""
    if not can_preview(found):
        return None, "File type is not previewable"

    data, read_error = _read_preview_data(found)
    if not data:
        return None, read_error or "Could not read image data from source"

    valid, reason = validate_preview_data(data, found.extension)
    if not valid:
        return None, reason

    png = _convert_to_png_bytes(data, found.extension)
    if png is None:
        return None, "Image could not be decoded (file may be truncated or corrupt)"

    if not _valid_png(png):
        return None, "Generated preview failed validation"

    return PreviewResult(png, "image/png"), None


def validate_preview_data(data: bytes, extension: str) -> tuple[bool, str]:
    """Reject empty, sparse, or structurally invalid carved image data."""
    if len(data) < MIN_PREVIEW_BYTES:
        return False, "Image data too small to preview"

    sample = data[: min(len(data), 4096)]
    if len(set(sample)) < MIN_ENTROPY_UNIQUE_BYTES:
        return False, "Image data appears blank or corrupt (low entropy)"

    null_ratio = sample.count(0) / len(sample)
    if null_ratio >= MAX_NULL_RATIO:
        return False, "Image data appears blank or corrupt (mostly zeros)"

    ext = extension.lower()
    if ext in ("jpg", "jpeg"):
        if not data.startswith(b"\xff\xd8"):
            return False, "Invalid JPEG header"
        if jpeg_dimensions(data) is None and not _jpeg_has_image_structure(data):
            return False, "JPEG image header is incomplete or corrupt"
        return True, ""

    if ext == "png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return False, "Invalid PNG header"
        if png_dimensions(data) is None:
            return False, "PNG image header is incomplete or corrupt"
        return True, ""

    if ext == "gif":
        if data[:6] not in (b"GIF87a", b"GIF89a"):
            return False, "Invalid GIF header"
        return True, ""

    if ext == "bmp":
        if not data.startswith(b"BM") or len(data) < 26:
            return False, "Invalid BMP header"
        if bmp_dimensions(data) is None:
            return False, "BMP header reports invalid dimensions"
        return True, ""

    if ext in ("tif", "tiff"):
        if data[:4] not in (b"II*\x00", b"MM\x00*"):
            return False, "Invalid TIFF header"
        return True, ""

    return False, "Unrecognized image format"


def render_preview_png(found: FoundFile) -> Optional[bytes]:
    result, _ = render_preview(found)
    return result.data if result else None


def _read_preview_data(found: FoundFile) -> tuple[Optional[bytes], Optional[str]]:
    if found.preview_note and os.path.isfile(found.preview_note):
        try:
            with open(found.preview_note, "rb") as handle:
                return handle.read(MAX_PREVIEW_BYTES), None
        except OSError as exc:
            return None, f"Cannot read file: {exc}"

    read_size = min(found.size, MAX_PREVIEW_BYTES)
    if read_size <= 0:
        return None, "Invalid carved file size"

    try:
        data = read_bytes(found.source_device, found.offset, read_size)
    except PermissionError:
        return None, (
            f"Permission denied reading {found.source_device}. "
            "Restart Recovery with sudo for raw disk previews."
        )
    except OSError as exc:
        return None, f"Cannot read source at offset 0x{found.offset:x}: {exc}"

    if not data:
        return None, "No data read from source"
    return data, None


def _valid_png(data: bytes) -> bool:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    if len(data) < MIN_PREVIEW_BYTES:
        return False
    return png_dimensions(data) is not None


def _convert_to_png_bytes(data: bytes, extension: str) -> Optional[bytes]:
    suffix = f".{extension.lower()}"
    source_path = None
    output_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            source_path = tmp.name

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as out:
            output_path = out.name

        result = subprocess.run(
            [
                "sips",
                "-s",
                "format",
                "png",
                source_path,
                "--out",
                output_path,
                "-Z",
                str(PREVIEW_MAX_DIMENSION),
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return None

        with open(output_path, "rb") as handle:
            png = handle.read()
        if not png:
            return None
        return png
    except OSError:
        return None
    finally:
        for path in (source_path, output_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def bmp_dimensions(data: bytes) -> Optional[tuple[int, int]]:
    if len(data) < 26 or not data.startswith(b"BM"):
        return None
    width = struct.unpack("<i", data[18:22])[0]
    height = abs(struct.unpack("<i", data[22:26])[0])
    if width <= 0 or height <= 0 or width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        return None
    return width, height


def png_dimensions(data: bytes) -> Optional[tuple[int, int]]:
    if len(data) < 24 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    width = struct.unpack(">I", data[16:20])[0]
    height = struct.unpack(">I", data[20:24])[0]
    if width <= 0 or height <= 0 or width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        return None
    return width, height


def _jpeg_sof_markers() -> tuple[int, ...]:
    return (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF)


def _jpeg_segment_len(data: bytes, index: int) -> Optional[int]:
    if index + 4 > len(data) or data[index] != 0xFF:
        return None
    segment_len = struct.unpack(">H", data[index + 2 : index + 4])[0]
    if segment_len < 2 or index + 2 + segment_len > len(data):
        return None
    return segment_len


def _jpeg_dimensions_from_sof(data: bytes, index: int) -> Optional[tuple[int, int]]:
    segment_len = _jpeg_segment_len(data, index)
    if segment_len is None or segment_len < 8 or index + 9 > len(data):
        return None
    height = struct.unpack(">H", data[index + 5 : index + 7])[0]
    width = struct.unpack(">H", data[index + 7 : index + 9])[0]
    if width <= 0 or height <= 0 or width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        return None
    if width * height > len(data) * 64:
        return None
    return width, height


def _jpeg_has_image_structure(data: bytes) -> bool:
    return jpeg_dimensions(data) is not None


def jpeg_dimensions(data: bytes) -> Optional[tuple[int, int]]:
    if not data.startswith(b"\xff\xd8"):
        return None
    index = 2
    limit = len(data)
    while index + 4 < limit:
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        if marker in _jpeg_sof_markers():
            return _jpeg_dimensions_from_sof(data, index)
        if marker in (0xD8, 0xD9):
            index += 2
            continue
        segment_len = _jpeg_segment_len(data, index)
        if segment_len is None:
            break
        index += 2 + segment_len
    return None
