from recovery.timestamps import extract_timestamps, format_timestamp


def test_pdf_creation_date() -> None:
    data = b"%PDF-1.4\n/CreationDate (D:20240315143000)"
    times = extract_timestamps(data, "pdf")
    assert times.created is not None
    assert format_timestamp(times.created).startswith("2024-03-15")


def test_missing_timestamps_return_dash() -> None:
    assert format_timestamp(None) == "—"
