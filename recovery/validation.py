from __future__ import annotations

from dataclasses import dataclass

from recovery.preview import validate_preview_data

CONFIDENCE_LEVELS = ("high", "medium", "low")
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

MIN_CARVE_BYTES = 128
MIN_ENTROPY_UNIQUE_BYTES = 12
MAX_NULL_RATIO = 0.92
ENTROPY_SAMPLE = 4096


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    confidence: str
    reason: str = ""


def meets_min_confidence(confidence: str, minimum: str) -> bool:
    if minimum == "low":
        return True
    return CONFIDENCE_RANK.get(confidence, 0) >= CONFIDENCE_RANK.get(minimum, 0)


def validate_carved(
    data: bytes,
    extension: str,
    signature_name: str,
    base_confidence: str,
) -> ValidationResult:
    """Validate carved bytes and return adjusted confidence or rejection."""
    if len(data) < MIN_CARVE_BYTES:
        return ValidationResult(False, base_confidence, "Carved data too small")

    entropy_ok, entropy_reason = _entropy_ok(data)
    if not entropy_ok:
        return ValidationResult(False, base_confidence, entropy_reason)

    ext = extension.lower()
    confidence = _normalize_confidence(base_confidence)

    if ext in ("jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff"):
        valid, reason = validate_preview_data(data, ext)
        if not valid:
            return ValidationResult(False, confidence, reason)
        confidence = _apply_footer(confidence, _has_image_footer(data, ext))
        return ValidationResult(True, confidence)

    if ext == "pdf":
        if not data.startswith(b"%PDF-"):
            return ValidationResult(False, confidence, "Invalid PDF header")
        confidence = _apply_footer(confidence, b"%%EOF" in data[-4096:])
        return ValidationResult(True, confidence)

    if ext in ("zip", "docx"):
        if not data.startswith(b"PK\x03\x04"):
            return ValidationResult(False, confidence, "Invalid ZIP header")
        has_eocd = b"PK\x05\x06" in data[-65536:]
        confidence = _apply_footer(confidence, has_eocd)
        return ValidationResult(True, confidence)

    if ext in ("mp4", "mov"):
        if not _looks_like_mp4(data):
            return ValidationResult(False, confidence, "Invalid MP4/MOV structure")
        confidence = _apply_footer(confidence, b"moov" in data[: min(len(data), 65536)])
        return ValidationResult(True, confidence)

    if ext == "avi":
        if not data.startswith(b"RIFF") or data[8:12] != b"AVI ":
            return ValidationResult(False, confidence, "Invalid AVI header")
        confidence = _apply_footer(confidence, len(data) >= 16)
        return ValidationResult(True, confidence)

    if ext == "mp3":
        if signature_name.startswith("MP3") and len(set(data[:512])) < 8:
            return ValidationResult(False, "low", "MP3 hit lacks audio data")
        return ValidationResult(True, "low")

    if ext == "html":
        closed = b"</html>" in data[-4096:].lower()
        confidence = _apply_footer("low", closed)
        return ValidationResult(True, confidence)

    if ext in ("doc", "xls") and data.startswith(b"\xd0\xcf\x11\xe0"):
        return ValidationResult(True, confidence)

    if ext == "rtf" and data.startswith(b"{\\rtf"):
        return ValidationResult(True, confidence)

    return ValidationResult(True, confidence)


def _normalize_confidence(value: str) -> str:
    lowered = value.lower()
    if lowered in CONFIDENCE_RANK:
        return lowered
    return "medium"


def _entropy_ok(data: bytes) -> tuple[bool, str]:
    sample = data[: min(len(data), ENTROPY_SAMPLE)]
    if len(set(sample)) < MIN_ENTROPY_UNIQUE_BYTES:
        return False, "Data appears blank or corrupt (low entropy)"
    null_ratio = sample.count(0) / len(sample)
    if null_ratio >= MAX_NULL_RATIO:
        return False, "Data appears blank or corrupt (mostly zeros)"
    return True, ""


def _apply_footer(confidence: str, has_footer: bool) -> str:
    if has_footer:
        return _raise_confidence(confidence)
    return _lower_confidence(confidence)


def _raise_confidence(confidence: str) -> str:
    if confidence == "medium":
        return "high"
    if confidence == "low":
        return "medium"
    return confidence


def _lower_confidence(confidence: str) -> str:
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return confidence


def _has_image_footer(data: bytes, extension: str) -> bool:
    ext = extension.lower()
    if ext in ("jpg", "jpeg"):
        tail = data[-64:]
        return b"\xff\xd9" in tail or data.endswith(b"\xff\xd9")
    if ext == "png":
        return b"IEND" in data[-128:]
    if ext == "gif":
        return data.endswith(b"\x3b") or data.endswith(b"\x00\x3b")
    if ext == "bmp":
        return len(data) >= 54
    if ext in ("tif", "tiff"):
        return len(data) >= 8
    return True


def _looks_like_mp4(data: bytes) -> bool:
    if len(data) < 12:
        return False
    if data[4:8] != b"ftyp":
        return False
    brand = data[8:12]
    return brand in (
        b"isom",
        b"iso2",
        b"mp41",
        b"mp42",
        b"avc1",
        b"qt  ",
        b"M4V ",
        b"MSNV",
        b"3gp4",
        b"3gp5",
    ) or brand.strip() != b""
