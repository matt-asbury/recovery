from __future__ import annotations

import plistlib
import subprocess
from dataclasses import replace
from typing import Any, Optional

from recovery.models import EncryptionInfo, VolumeInfo


def enrich_volume_encryption(
    volume: VolumeInfo,
    *,
    apfs_index: Optional[dict[str, dict[str, Any]]] = None,
) -> VolumeInfo:
    """Attach encryption metadata from diskutil."""
    if volume.is_disk_image:
        return replace(volume, encryption=EncryptionInfo.unknown())

    if apfs_index is None:
        apfs_index = load_apfs_volume_index()
    encryption = probe_encryption(volume.device_id, apfs_index=apfs_index)
    return replace(volume, encryption=encryption)


def load_apfs_volume_index() -> dict[str, dict[str, Any]]:
    """Build a lookup of APFS volume device paths to apfs list entries."""
    try:
        output = subprocess.check_output(
            ["diskutil", "apfs", "list", "-plist"],
            stderr=subprocess.STDOUT,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}

    plist = plistlib.loads(output)
    index: dict[str, dict[str, Any]] = {}
    for container in plist.get("Containers", []):
        for volume in container.get("Volumes", []):
            device = volume.get("DeviceIdentifier")
            if not device:
                continue
            index[device] = volume
            index[f"/dev/{device}"] = volume
    return index


def probe_encryption(
    device_path: str,
    *,
    apfs_index: Optional[dict[str, dict[str, Any]]] = None,
) -> EncryptionInfo:
    """Detect encryption state for a block device using diskutil."""
    device = _normalize_device(device_path)
    info: dict[str, Any] = {}
    try:
        output = subprocess.check_output(
            ["diskutil", "info", "-plist", device],
            stderr=subprocess.STDOUT,
        )
        info = plistlib.loads(output)
    except (subprocess.CalledProcessError, FileNotFoundError, plistlib.InvalidFileException):
        info = {}

    apfs_entry = None
    if apfs_index is not None:
        apfs_entry = apfs_index.get(device) or apfs_index.get(device.replace("/dev/", ""))

    return parse_encryption_info(info, apfs_entry=apfs_entry)


def parse_encryption_info(
    info: dict[str, Any],
    *,
    apfs_entry: Optional[dict[str, Any]] = None,
) -> EncryptionInfo:
    """Parse diskutil info and optional APFS list entry into EncryptionInfo."""
    encrypted = _truthy(
        info.get("Encrypted"),
        info.get("FileVault"),
        info.get("MediaEncrypted"),
        apfs_entry.get("Encrypted") if apfs_entry else None,
    )
    locked = _truthy(
        info.get("Locked"),
        apfs_entry.get("Locked") if apfs_entry else None,
    )
    encryption_type = str(
        info.get("EncryptionType")
        or (apfs_entry or {}).get("EncryptionType")
        or ""
    ).strip()

    content = str(info.get("Content") or info.get("FileSystemPersonality") or "")
    method = _encryption_method(content, encryption_type)

    if not encrypted and not encryption_type:
        return EncryptionInfo.none()

    if locked:
        return EncryptionInfo(
            status="locked",
            method=method,
            summary="Encrypted and locked",
            workflow=_locked_workflow(info.get("DeviceIdentifier") or ""),
        )

    return EncryptionInfo(
        status="unlocked",
        method=method,
        summary="Encrypted (unlocked)",
        workflow=_unlocked_workflow(),
    )


def scan_mode_error(volume: VolumeInfo, mode: str) -> Optional[str]:
    """Return an error message when the scan mode is inappropriate, else None."""
    enc = volume.encryption

    if enc.is_locked:
        return (
            "This volume is encrypted and locked. Unlock it before scanning. "
            f"{enc.workflow}"
        )

    if mode == "quick":
        if volume.is_disk_image:
            return "Quick scan is not available for disk images."
        if not volume.mount_point:
            if enc.is_encrypted:
                return (
                    "Mount the unlocked volume before running a Quick scan. "
                    f"{enc.workflow}"
                )
            return "Quick scan requires a mounted volume. Use deep scan instead."
        if not enc.allows_filesystem_scan:
            return f"Filesystem scan is not available. {enc.workflow}"
        return None

    if mode == "deep" and enc.blocks_raw_carve:
        return (
            "Deep scan cannot recover readable files from encrypted media at the block level. "
            f"{enc.workflow}"
        )

    if mode == "hybrid":
        if enc.is_encrypted and not volume.mount_point:
            return (
                "Hybrid scan on encrypted volumes requires the volume to be mounted "
                f"for the filesystem walk. {enc.workflow}"
            )
        return None

    return None


def encryption_to_dict(info: EncryptionInfo) -> dict[str, object]:
    return {
        "status": info.status,
        "method": info.method,
        "summary": info.summary,
        "workflow": info.workflow,
        "is_encrypted": info.is_encrypted,
        "is_locked": info.is_locked,
        "blocks_raw_carve": info.blocks_raw_carve,
        "allows_filesystem_scan": info.allows_filesystem_scan,
    }


def _normalize_device(device_path: str) -> str:
    path = device_path.strip()
    if path.startswith("/dev/"):
        return path
    return f"/dev/{path}"


def _truthy(*values: Any) -> bool:
    for value in values:
        if value is None:
            continue
        if isinstance(value, bool):
            if value:
                return True
            continue
        text = str(value).strip().lower()
        if text in {"yes", "true", "1", "encrypted", "locked"}:
            return True
    return False


def _encryption_method(content: str, encryption_type: str) -> str:
    lowered = content.lower()
    if "apfs" in lowered:
        return "apfs"
    if "corestorage" in lowered or "core storage" in lowered:
        return "corestorage"
    if encryption_type:
        return "filevault"
    return "unknown"


def _locked_workflow(device_identifier: str) -> str:
    device = device_identifier or "diskXsY"
    return (
        f"Unlock with Disk Utility, or run: diskutil apfs unlockVolume /dev/{device} "
        "(use diskutil cs unlockVolume for older Core Storage volumes). "
        "After unlocking, mount the volume and use Quick or Hybrid scan — raw carving "
        "reads encrypted bytes and will not recover your files."
    )


def _unlocked_workflow() -> str:
    return (
        "Mount the volume and use Quick or Hybrid scan to read files through the "
        "filesystem. Deep scan and carving read encrypted blocks on disk and cannot "
        "recover readable files without the volume key."
    )
