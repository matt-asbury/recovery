from recovery.preview import jpeg_dimensions, validate_preview_data


def test_validate_rejects_mostly_zero_jpeg() -> None:
    data = b"\xff\xd8\xff" + b"\x00" * 2000
    valid, reason = validate_preview_data(data, "jpg")
    assert valid is False
    assert "blank" in reason.lower() or "corrupt" in reason.lower()


def test_validate_rejects_fake_sof_dimensions() -> None:
    data = (
        b"\xff\xd8\xff\xc7"
        + b"\x29\x6e"
        + bytes(range(256))
    )
    assert jpeg_dimensions(data) is None
    valid, reason = validate_preview_data(data, "jpg")
    assert valid is False
