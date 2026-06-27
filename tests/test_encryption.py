from recovery.encryption import (
    parse_encryption_info,
    scan_mode_error,
)
from recovery.models import EncryptionInfo, VolumeInfo


def _volume(**kwargs) -> VolumeInfo:
    defaults = {
        "device_id": "/dev/disk3s1",
        "name": "Macintosh HD",
        "size_bytes": 1024**3,
        "mount_point": None,
        "file_system": "APFS",
        "is_removable": False,
        "is_internal": True,
        "whole_disk": False,
    }
    defaults.update(kwargs)
    return VolumeInfo(**defaults)


def test_parse_locked_apfs_volume() -> None:
    info = parse_encryption_info(
        {
            "DeviceIdentifier": "disk3s1",
            "Content": "Apple_APFS",
            "Encrypted": True,
            "Locked": True,
            "EncryptionType": "AES-XTS",
        }
    )
    assert info.status == "locked"
    assert info.is_encrypted
    assert info.blocks_raw_carve
    assert "unlockVolume" in info.workflow


def test_parse_unlocked_encrypted_volume() -> None:
    info = parse_encryption_info(
        {
            "DeviceIdentifier": "disk3s1",
            "FileVault": True,
            "Encrypted": "Yes",
            "Locked": False,
        }
    )
    assert info.status == "unlocked"
    assert info.allows_filesystem_scan
    assert "Quick or Hybrid" in info.workflow


def test_parse_unencrypted_volume() -> None:
    info = parse_encryption_info({"Encrypted": False, "FileVault": False})
    assert info.status == "none"
    assert not info.blocks_raw_carve


def test_scan_mode_error_blocks_deep_on_encrypted() -> None:
    volume = _volume(encryption=EncryptionInfo(status="unlocked", summary="Encrypted"))
    error = scan_mode_error(volume, "deep")
    assert error is not None
    assert "encrypted" in error.lower()


def test_scan_mode_error_allows_hybrid_when_mounted() -> None:
    volume = _volume(
        mount_point="/Volumes/Data",
        encryption=EncryptionInfo(status="unlocked", summary="Encrypted"),
    )
    assert scan_mode_error(volume, "hybrid") is None


def test_scan_mode_error_blocks_hybrid_when_unmounted() -> None:
    volume = _volume(encryption=EncryptionInfo(status="unlocked", summary="Encrypted"))
    error = scan_mode_error(volume, "hybrid")
    assert error is not None
    assert "mounted" in error.lower()


def test_scan_mode_error_blocks_locked_volume() -> None:
    volume = _volume(
        encryption=EncryptionInfo(
            status="locked",
            summary="Encrypted and locked",
            workflow="Unlock first.",
        )
    )
    assert scan_mode_error(volume, "quick") is not None
    assert scan_mode_error(volume, "deep") is not None
