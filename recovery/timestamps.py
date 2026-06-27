from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

EXIF_DATETIME_RE = re.compile(rb"(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})")
PDF_CREATION_RE = re.compile(rb"/CreationDate\s*\(D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})")
PDF_MOD_RE = re.compile(rb"/ModDate\s*\(D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})")
MP4_EPOCH = datetime(1904, 1, 1)
HEADER_BYTES = 256 * 1024


@dataclass(frozen=True)
class TimestampInfo:
    created: Optional[float] = None
    modified: Optional[float] = None

    @property
    def display(self) -> Optional[float]:
        """Prefer creation time; fall back to modified when creation is unknown."""
        return self.created if self.created is not None else self.modified


def format_timestamp(epoch: Optional[float]) -> str:
    if epoch is None:
        return "—"
    try:
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "—"


def stat_timestamps(path: str) -> TimestampInfo:
    """Read creation/modified times from a file on disk (quick scan)."""
    try:
        stat = os.stat(path)
    except OSError:
        return TimestampInfo()

    created: Optional[float] = None
    birthtime = getattr(stat, "st_birthtime", None)
    if birthtime is not None and birthtime > 0:
        created = float(birthtime)

    modified = float(stat.st_mtime) if stat.st_mtime > 0 else None
    return TimestampInfo(created=created, modified=modified)


def extract_timestamps(data: bytes, extension: str) -> TimestampInfo:
    """Best-effort created/modified times from carved file headers."""
    if not data:
        return TimestampInfo()

    ext = extension.lower()
    header = data[:HEADER_BYTES]

    if ext in ("jpg", "jpeg"):
        return _extract_jpeg_timestamps(header)
    if ext == "pdf":
        return _extract_pdf_timestamps(header)
    if ext in ("mp4", "mov"):
        return _extract_mp4_timestamps(header)
    if ext == "png":
        return _extract_png_timestamps(header)
    if ext in ("zip", "docx"):
        modified = _extract_zip_modified(header)
        return TimestampInfo(modified=modified)

    return TimestampInfo()


def extract_timestamp(data: bytes, extension: str) -> Optional[float]:
    """Backward-compatible helper returning the preferred display timestamp."""
    return extract_timestamps(data, extension).display


def _extract_jpeg_timestamps(data: bytes) -> TimestampInfo:
    exif = data.find(b"Exif\x00\x00")
    search = data[exif : exif + HEADER_BYTES] if exif != -1 else data

    created = _exif_tag_datetime(search, b"DateTimeOriginal")
    if created is None:
        created = _exif_tag_datetime(search, b"DateTimeDigitized")
    modified = _exif_tag_datetime(search, b"DateTime")

    if created is None:
        created = _first_exif_datetime(search)
    return TimestampInfo(created=created, modified=modified)


def _exif_tag_datetime(data: bytes, tag: bytes) -> Optional[float]:
    index = data.find(tag)
    if index == -1:
        return None
    snippet = data[index + len(tag) : index + len(tag) + 48]
    match = EXIF_DATETIME_RE.search(snippet)
    if not match:
        return None
    return _parse_exif_datetime(match.group(0).decode("ascii", errors="ignore"))


def _first_exif_datetime(data: bytes) -> Optional[float]:
    for match in EXIF_DATETIME_RE.finditer(data):
        parsed = _parse_exif_datetime(match.group(0).decode("ascii", errors="ignore"))
        if parsed is not None:
            return parsed
    return None


def _parse_exif_datetime(text: str) -> Optional[float]:
    try:
        dt = datetime.strptime(text, "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None
    if dt.year < 1990 or dt.year > 2035:
        return None
    return dt.timestamp()


def _extract_pdf_timestamps(data: bytes) -> TimestampInfo:
    created = _pdf_match(PDF_CREATION_RE, data)
    modified = _pdf_match(PDF_MOD_RE, data)
    return TimestampInfo(created=created, modified=modified)


def _pdf_match(pattern: re.Pattern[bytes], data: bytes) -> Optional[float]:
    match = pattern.search(data)
    if not match:
        return None
    parts = [int(match.group(i).decode()) for i in range(1, 7)]
    try:
        dt = datetime(*parts)
    except ValueError:
        return None
    if dt.year < 1990 or dt.year > 2035:
        return None
    return dt.timestamp()


def _extract_mp4_timestamps(data: bytes) -> TimestampInfo:
    index = 0
    while index + 8 <= len(data):
        size = struct.unpack(">I", data[index : index + 4])[0]
        atom = data[index + 4 : index + 8]
        if size < 8:
            break
        if index + size > len(data):
            break
        if atom == b"mvhd" and size >= 32:
            return _parse_mvhd_timestamps(data[index + 8 : index + size])
        index += size
    return TimestampInfo()


def _parse_mvhd_timestamps(body: bytes) -> TimestampInfo:
    if len(body) < 20:
        return TimestampInfo()
    version = body[0]
    if version == 0:
        if len(body) < 20:
            return TimestampInfo()
        created = _mp4_seconds(struct.unpack(">I", body[4:8])[0])
        modified = _mp4_seconds(struct.unpack(">I", body[8:12])[0])
        return TimestampInfo(created=created, modified=modified)
    if version == 1:
        if len(body) < 32:
            return TimestampInfo()
        created = _mp4_seconds(struct.unpack(">Q", body[4:12])[0])
        modified = _mp4_seconds(struct.unpack(">Q", body[12:20])[0])
        return TimestampInfo(created=created, modified=modified)
    return TimestampInfo()


def _mp4_seconds(raw: int) -> Optional[float]:
    if raw <= 0:
        return None
    return MP4_EPOCH.timestamp() + raw


def _extract_png_timestamps(data: bytes) -> TimestampInfo:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return TimestampInfo()
    index = 8
    while index + 12 <= len(data):
        length = struct.unpack(">I", data[index : index + 4])[0]
        chunk_type = data[index + 4 : index + 8]
        chunk_start = index + 8
        chunk_end = chunk_start + length
        if chunk_end > len(data):
            break
        if chunk_type == b"tIME" and length >= 7:
            year = struct.unpack(">H", data[chunk_start : chunk_start + 2])[0]
            month = data[chunk_start + 2]
            day = data[chunk_start + 3]
            hour = data[chunk_start + 4]
            minute = data[chunk_start + 5]
            second = data[chunk_start + 6]
            try:
                dt = datetime(year, month, day, hour, minute, second)
            except ValueError:
                return TimestampInfo()
            if 1990 <= dt.year <= 2035:
                ts = dt.timestamp()
                # PNG tIME is last modification, not creation.
                return TimestampInfo(modified=ts)
            return TimestampInfo()
        index = chunk_end + 4
    return TimestampInfo()


def _extract_zip_modified(data: bytes) -> Optional[float]:
    if len(data) < 14 or not data.startswith(b"PK\x03\x04"):
        return None
    dos_time = struct.unpack("<H", data[10:12])[0]
    dos_date = struct.unpack("<H", data[12:14])[0]
    return _dos_datetime_to_epoch(dos_date, dos_time)


def _dos_datetime_to_epoch(dos_date: int, dos_time: int) -> Optional[float]:
    if dos_date == 0 and dos_time == 0:
        return None
    day = dos_date & 0x1F
    month = (dos_date >> 5) & 0x0F
    year = ((dos_date >> 9) & 0x7F) + 1980
    second = (dos_time & 0x1F) * 2
    minute = (dos_time >> 5) & 0x3F
    hour = (dos_time >> 11) & 0x1F
    try:
        dt = datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None
    if year < 1990 or year > 2035:
        return None
    return dt.timestamp()
