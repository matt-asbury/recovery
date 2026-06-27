from __future__ import annotations

import os
import plistlib
import subprocess
from dataclasses import replace
from typing import Optional

from recovery.models import VolumeInfo
from recovery.partitions import parse_partitions
from recovery.encryption import enrich_volume_encryption, load_apfs_volume_index


def volume_from_image(image_path: str) -> VolumeInfo:
    """Build a scan target from a disk image file (.img, .dmg, .raw, etc.)."""
    path = os.path.abspath(os.path.expanduser(image_path))
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Disk image not found: {path}")

    size = os.path.getsize(path)
    if size <= 0:
        raise ValueError(f"Disk image is empty: {path}")

    name = os.path.basename(path)
    volume = VolumeInfo(
        device_id=path,
        name=name,
        size_bytes=size,
        mount_point=None,
        file_system="disk_image",
        is_removable=True,
        is_internal=False,
        whole_disk=True,
        is_disk_image=True,
        image_path=path,
    )
    return enrich_volume_encryption(enrich_volume_partitions(volume))


def enrich_volume_partitions(volume: VolumeInfo) -> VolumeInfo:
    """Parse partition tables for whole-disk images and raw devices."""
    if not volume.whole_disk and not volume.is_disk_image:
        return volume

    read_path = volume.read_path
    try:
        partitions = parse_partitions(read_path, volume.size_bytes)
    except OSError:
        return volume
    if not partitions:
        return volume

    return replace(volume, partitions=tuple(partitions))


def volume_for_partition(volume: VolumeInfo, partition_index: Optional[int]) -> VolumeInfo:
    """Return a scan target scoped to one partition, or the full volume."""
    if partition_index is None or partition_index < 0:
        return replace(volume, scan_start_byte=0, scan_size_bytes=None)

    if partition_index >= len(volume.partitions):
        raise ValueError(f"Invalid partition index: {partition_index}")

    partition = volume.partitions[partition_index]
    label = partition.name or partition.type_label
    return replace(
        volume,
        name=f"{volume.name} — {label}",
        scan_start_byte=partition.start_byte,
        scan_size_bytes=partition.size_bytes,
        whole_disk=False,
    )


def list_volumes(include_internal: bool = True) -> list[VolumeInfo]:
    """Enumerate attached disks and partitions using diskutil."""
    try:
        output = subprocess.check_output(
            ["diskutil", "list", "-plist"],
            stderr=subprocess.STDOUT,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError("Failed to list disks. Is this running on macOS?") from exc

    plist = plistlib.loads(output)
    volumes: list[VolumeInfo] = []
    seen: set[str] = set()
    apfs_index = load_apfs_volume_index()

    for entry in plist.get("AllDisksAndPartitions", []):
        _collect_volumes(entry, plist, volumes, seen, include_internal, apfs_index=apfs_index)

    volumes.sort(key=lambda v: (v.is_internal, v.name.lower()))
    return volumes


def _collect_volumes(
    entry: dict,
    plist: dict,
    volumes: list[VolumeInfo],
    seen: set[str],
    include_internal: bool,
    *,
    apfs_index: dict,
    parent_internal: Optional[bool] = None,
) -> None:
    info = _entry_to_volume(entry, parent_internal=parent_internal, apfs_index=apfs_index)
    if info and _should_include(info, include_internal) and info.device_id not in seen:
        seen.add(info.device_id)
        volumes.append(info)
        parent_internal = info.is_internal

    for key in ("Partitions", "APFSVolumes"):
        for child in entry.get(key, []):
            _collect_volumes(
                child,
                plist,
                volumes,
                seen,
                include_internal,
                apfs_index=apfs_index,
                parent_internal=parent_internal,
            )


def _should_include(info: VolumeInfo, include_internal: bool) -> bool:
    if include_internal:
        return True
    return not info.is_internal


def _entry_to_volume(
    entry: dict,
    *,
    apfs_index: dict,
    parent_internal: Optional[bool] = None,
) -> Optional[VolumeInfo]:
    device_id = entry.get("DeviceIdentifier")
    if not device_id:
        return None

    size = int(entry.get("Size", 0) or 0)
    if size <= 0:
        return None

    content = entry.get("Content", "")
    if content in ("GUID_partition_scheme", "FDisk_partition_scheme"):
        volume = VolumeInfo(
            device_id=f"/dev/{device_id}",
            name=str(entry.get("VolumeName") or content or device_id),
            size_bytes=size,
            mount_point=entry.get("MountPoint"),
            file_system=content,
            is_removable=bool(entry.get("Removable") or entry.get("External")),
            is_internal=_is_internal(entry, parent_internal),
            whole_disk=True,
        )
        volume = enrich_volume_partitions(volume)
        return enrich_volume_encryption(volume, apfs_index=apfs_index)

    if content == "Apple_APFS_Container":
        volume = VolumeInfo(
            device_id=f"/dev/{device_id}",
            name=str(entry.get("VolumeName") or "APFS Container"),
            size_bytes=size,
            mount_point=entry.get("MountPoint"),
            file_system=content,
            is_removable=bool(entry.get("Removable") or entry.get("External")),
            is_internal=_is_internal(entry, parent_internal),
            whole_disk=True,
        )
        return enrich_volume_encryption(volume, apfs_index=apfs_index)

    skip_contents = {
        "EFI",
        "Apple_APFS_Recovery",
        "Apple_Boot",
    }
    if content in skip_contents and not entry.get("VolumeName"):
        return None

    name = (
        entry.get("VolumeName")
        or entry.get("MediaName")
        or content
        or device_id
    )

    volume = VolumeInfo(
        device_id=f"/dev/{device_id}",
        name=str(name),
        size_bytes=size,
        mount_point=entry.get("MountPoint"),
        file_system=entry.get("FileSystemPersonality") or content or None,
        is_removable=bool(entry.get("Removable") or entry.get("External")),
        is_internal=_is_internal(entry, parent_internal),
        whole_disk=False,
    )
    return enrich_volume_encryption(volume, apfs_index=apfs_index)


def _is_internal(entry: dict, parent_internal: Optional[bool]) -> bool:
    if parent_internal is not None:
        return parent_internal
    removable = bool(entry.get("Removable") or entry.get("External"))
    internal = bool(entry.get("OSInternal") or entry.get("Internal"))
    return internal and not removable


def get_volume_size(device_path: str) -> int:
    """Return size in bytes for a device node."""
    try:
        output = subprocess.check_output(
            ["diskutil", "info", "-plist", device_path],
            stderr=subprocess.STDOUT,
        )
        info = plistlib.loads(output)
        return int(info.get("TotalSize", 0) or info.get("Size", 0) or 0)
    except subprocess.CalledProcessError:
        return 0
