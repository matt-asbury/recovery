from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from recovery.models import FileCategory


@dataclass(frozen=True)
class FileSignature:
    name: str
    extension: str
    category: FileCategory
    pattern: bytes
    estimate_size: Callable[[bytes, int, int], Optional[int]]
    confidence: str = "medium"


def _find_jpeg_end(data: bytes, start: int, max_size: int) -> Optional[int]:
    limit = min(len(data), start + max_size)
    idx = data.find(b"\xff\xd9", start + 2, limit)
    if idx == -1:
        return None
    return idx - start + 2


def _find_png_end(data: bytes, start: int, max_size: int) -> Optional[int]:
    pos = start + 8
    limit = min(len(data), start + max_size)
    while pos + 12 <= limit:
        if pos + 8 > limit:
            return None
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type = data[pos + 4 : pos + 8]
        end = pos + 12 + length
        if end > limit:
            return None
        if chunk_type == b"IEND":
            return end - start
        pos = end
    return None


def _find_gif_end(data: bytes, start: int, max_size: int) -> Optional[int]:
    limit = min(len(data), start + max_size)
    trailer = data.find(b"\x00\x3b", start + 6, limit)
    if trailer == -1:
        trailer = data.find(b"\x3b", start + 6, limit)
    if trailer == -1:
        return None
    return trailer - start + 1


def _find_pdf_end(data: bytes, start: int, max_size: int) -> Optional[int]:
    limit = min(len(data), start + max_size)
    eof = data.rfind(b"%%EOF", start, limit)
    if eof == -1:
        return None
    end = eof + 5
    while end < limit and data[end : end + 1] in (b"\n", b"\r", b" "):
        end += 1
    return end - start


def _find_zip_end(data: bytes, start: int, max_size: int) -> Optional[int]:
    limit = min(len(data), start + max_size)
    eocd = data.rfind(b"PK\x05\x06", start, limit)
    if eocd == -1:
        return min(max_size, limit - start)
    comment_len = struct.unpack("<H", data[eocd + 20 : eocd + 22])[0]
    end = eocd + 22 + comment_len
    if end > limit:
        return min(max_size, limit - start)
    return end - start


def _find_mp4_end(data: bytes, start: int, max_size: int) -> Optional[int]:
    pos = start
    limit = min(len(data), start + max_size)
    total = 0
    while pos + 8 <= limit and total < max_size:
        size = struct.unpack(">I", data[pos : pos + 4])[0]
        atom_type = data[pos + 4 : pos + 8]
        if size == 0:
            total = limit - start
            break
        if size == 1:
            if pos + 16 > limit:
                break
            size = struct.unpack(">Q", data[pos + 8 : pos + 16])[0]
        if size < 8 or pos + size > limit:
            break
        total = pos + size - start
        if atom_type in (b"mdat", b"moov", b"free", b"skip", b"wide"):
            pos += size
            continue
        pos += size
    if total >= 256:
        return total
    return min(max_size, 4 * 1024 * 1024)


def _fixed_cap(cap: int) -> Callable[[bytes, int, int], Optional[int]]:
    def estimate(data: bytes, start: int, max_size: int) -> Optional[int]:
        return min(cap, max_size, len(data) - start)

    return estimate


def _read_bmp_size(data: bytes, start: int, max_size: int) -> Optional[int]:
    if start + 6 > len(data):
        return None
    size = struct.unpack("<I", data[start + 2 : start + 6])[0]
    if size < 54 or size > min(max_size, 200 * 1024 * 1024):
        return None
    if start + size > len(data):
        return min(len(data) - start, size)
    return size


def _read_riff_size(data: bytes, start: int, max_size: int) -> Optional[int]:
    if start + 8 > len(data):
        return None
    if data[start + 4 : start + 8] not in (b"AVI ", b"WAVE", b"WEBP"):
        return None
    size = struct.unpack("<I", data[start + 4 : start + 8])[0]
    total = size + 8
    cap = min(max_size, 4 * 1024 * 1024 * 1024)
    if total < 16 or total > cap:
        return None
    if start + total > len(data):
        return min(len(data) - start, total)
    return total


def _find_html_end(data: bytes, start: int, max_size: int) -> Optional[int]:
    limit = min(len(data), start + max_size)
    match = re.search(rb"</html>", data[start:limit], re.IGNORECASE)
    if match:
        return match.end()
    return min(max_size, limit - start)


SIGNATURES: list[FileSignature] = [
    FileSignature(
        "JPEG",
        "jpg",
        FileCategory.IMAGE,
        b"\xff\xd8\xff",
        _find_jpeg_end,
        "high",
    ),
    FileSignature(
        "PNG",
        "png",
        FileCategory.IMAGE,
        b"\x89PNG\r\n\x1a\n",
        _find_png_end,
        "high",
    ),
    FileSignature(
        "GIF",
        "gif",
        FileCategory.IMAGE,
        b"GIF87a",
        _find_gif_end,
        "high",
    ),
    FileSignature(
        "GIF",
        "gif",
        FileCategory.IMAGE,
        b"GIF89a",
        _find_gif_end,
        "high",
    ),
    FileSignature(
        "BMP",
        "bmp",
        FileCategory.IMAGE,
        b"BM",
        _read_bmp_size,
        "medium",
    ),
    FileSignature(
        "TIFF LE",
        "tif",
        FileCategory.IMAGE,
        b"II*\x00",
        _fixed_cap(50 * 1024 * 1024),
        "low",
    ),
    FileSignature(
        "TIFF BE",
        "tif",
        FileCategory.IMAGE,
        b"MM\x00*",
        _fixed_cap(50 * 1024 * 1024),
        "low",
    ),
    FileSignature(
        "PDF",
        "pdf",
        FileCategory.DOCUMENT,
        b"%PDF-",
        _find_pdf_end,
        "high",
    ),
    FileSignature(
        "ZIP",
        "zip",
        FileCategory.ARCHIVE,
        b"PK\x03\x04",
        _find_zip_end,
        "medium",
    ),
    FileSignature(
        "DOCX",
        "docx",
        FileCategory.DOCUMENT,
        b"PK\x03\x04",
        _find_zip_end,
        "medium",
    ),
    FileSignature(
        "MP4",
        "mp4",
        FileCategory.VIDEO,
        b"\x00\x00\x00\x18ftyp",
        _find_mp4_end,
        "medium",
    ),
    FileSignature(
        "MP4",
        "mp4",
        FileCategory.VIDEO,
        b"\x00\x00\x00\x20ftyp",
        _find_mp4_end,
        "medium",
    ),
    FileSignature(
        "MOV",
        "mov",
        FileCategory.VIDEO,
        b"\x00\x00\x00\x14ftypqt  ",
        _find_mp4_end,
        "medium",
    ),
    FileSignature(
        "AVI",
        "avi",
        FileCategory.VIDEO,
        b"RIFF",
        _read_riff_size,
        "medium",
    ),
    FileSignature(
        "WAV",
        "wav",
        FileCategory.OTHER,
        b"RIFF",
        _read_riff_size,
        "medium",
    ),
    FileSignature(
        "MP3 ID3",
        "mp3",
        FileCategory.OTHER,
        b"ID3",
        _fixed_cap(15 * 1024 * 1024),
        "low",
    ),
    FileSignature(
        "MP3 frame",
        "mp3",
        FileCategory.OTHER,
        b"\xff\xfb",
        _fixed_cap(15 * 1024 * 1024),
        "low",
    ),
    FileSignature(
        "RTF",
        "rtf",
        FileCategory.DOCUMENT,
        b"{\\rtf",
        _fixed_cap(20 * 1024 * 1024),
        "medium",
    ),
    FileSignature(
        "Old DOC",
        "doc",
        FileCategory.DOCUMENT,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        _fixed_cap(50 * 1024 * 1024),
        "medium",
    ),
    FileSignature(
        "Old XLS",
        "xls",
        FileCategory.DOCUMENT,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        _fixed_cap(50 * 1024 * 1024),
        "medium",
    ),
    FileSignature(
        "HTML",
        "html",
        FileCategory.DOCUMENT,
        b"<!DOCTYPE html",
        _find_html_end,
        "low",
    ),
    FileSignature(
        "HTML",
        "html",
        FileCategory.DOCUMENT,
        b"<html",
        _find_html_end,
        "low",
    ),
]


CATEGORY_EXTENSIONS: dict[FileCategory, set[str]] = {}
for sig in SIGNATURES:
    CATEGORY_EXTENSIONS.setdefault(sig.category, set()).add(sig.extension)
