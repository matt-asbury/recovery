from recovery.validation import (
    meets_min_confidence,
    validate_carved,
)


def test_rejects_mostly_zero_jpeg() -> None:
    data = b"\xff\xd8\xff" + b"\x00" * 2000
    result = validate_carved(data, "jpg", "JPEG", "high")
    assert not result.accepted


def test_accepts_pdf_with_eof() -> None:
    data = b"%PDF-1.4\n" + b"% content\n" * 20 + b"\n%%EOF\n"
    result = validate_carved(data, "pdf", "PDF", "high")
    assert result.accepted
    assert result.confidence == "high"


def test_downgrades_pdf_without_eof() -> None:
    data = b"%PDF-1.4\n" + b"% content\n" * 20
    result = validate_carved(data, "pdf", "PDF", "high")
    assert result.accepted
    assert result.confidence == "medium"


def test_meets_min_confidence() -> None:
    assert meets_min_confidence("high", "medium")
    assert meets_min_confidence("medium", "medium")
    assert not meets_min_confidence("low", "medium")
    assert meets_min_confidence("low", "low")
