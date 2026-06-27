from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional

from recovery.device_io import read_bytes
from recovery.models import FileCategory, FoundFile, VolumeInfo
from recovery.signatures import CATEGORY_EXTENSIONS
from recovery.timestamps import stat_timestamps

FAT32_LABEL = b"FAT32   "
SCAN_EXTENSIONS = {
    f".{extension}"
    for extensions in CATEGORY_EXTENSIONS.values()
    for extension in extensions
}


@dataclass(frozen=True)
class FAT32Layout:
    partition_offset: int
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    fat_start: int
    fat_size_bytes: int
    data_start: int
    num_entries: int


def walk_filesystem(
    mount_point: str,
    *,
    categories: Optional[set[str]] = None,
) -> list[FoundFile]:
    """Walk a mounted volume and return recoverable files with original paths."""
    found: list[FoundFile] = []
    for root, _dirs, files in os.walk(mount_point):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue

            path = os.path.join(root, name)
            try:
                stat = os.stat(path)
            except OSError:
                continue

            ext_clean = ext.lstrip(".")
            category = _category_for_extension(ext_clean)
            if categories and category.value not in categories:
                continue

            times = stat_timestamps(path)
            found.append(
                FoundFile(
                    offset=0,
                    size=stat.st_size,
                    extension=ext_clean or "bin",
                    category=category,
                    signature_name="Filesystem",
                    source_device=path,
                    confidence="high",
                    preview_note=path,
                    created_at=times.created,
                    modified_at=times.modified,
                    source_kind="filesystem",
                )
            )
    return found


def unallocated_regions(volume: VolumeInfo) -> Optional[list[tuple[int, int]]]:
    """Return byte ranges to carve, or None when the full scan region should be used."""
    scan_start = max(0, volume.scan_start_byte)
    scan_size = volume.scan_size_bytes or max(0, volume.size_bytes - scan_start)
    scan_end = scan_start + scan_size

    fat_regions = fat32_unallocated_regions(
        volume.read_path,
        partition_offset=scan_start,
        partition_size=scan_size,
    )
    if fat_regions is not None:
        return _clip_regions(fat_regions, scan_start, scan_end)

    return None


def fat32_unallocated_regions(
    path: str,
    *,
    partition_offset: int,
    partition_size: int,
) -> Optional[list[tuple[int, int]]]:
    """Parse a FAT32 partition and return contiguous free-space byte ranges."""
    if partition_size < 512:
        return None

    header = read_bytes(path, partition_offset, 512)
    layout = _parse_fat32_layout(header, partition_offset, partition_size)
    if layout is None:
        return None

    fat_data = read_bytes(path, layout.fat_start, layout.fat_size_bytes)
    if len(fat_data) < layout.num_entries * 4:
        return None

    free_clusters: list[int] = []
    data_bytes = max(0, (partition_offset + partition_size) - layout.data_start)
    max_cluster = min(
        layout.num_entries - 1,
        1 + (data_bytes // layout.cluster_size),
    )
    for cluster in range(2, max_cluster + 1):
        entry_offset = cluster * 4
        if entry_offset + 4 > len(fat_data):
            break
        entry = struct.unpack("<I", fat_data[entry_offset : entry_offset + 4])[0]
        if entry & 0x0FFFFFFF == 0:
            free_clusters.append(cluster)

    return _clusters_to_regions(layout, free_clusters, partition_offset + partition_size)


def _parse_fat32_layout(
    header: bytes,
    partition_offset: int,
    partition_size: int,
) -> Optional[FAT32Layout]:
    if len(header) < 0x5A or header[0x52:0x5A] != FAT32_LABEL:
        return None

    bytes_per_sector = struct.unpack("<H", header[0x0B:0x0D])[0]
    sectors_per_cluster = header[0x0D]
    reserved_sectors = struct.unpack("<H", header[0x0E:0x10])[0]
    num_fats = header[0x10]
    fat_size_sectors = struct.unpack("<I", header[0x24:0x28])[0]

    if bytes_per_sector < 512 or sectors_per_cluster <= 0 or num_fats <= 0:
        return None
    if fat_size_sectors <= 0:
        return None

    cluster_size = bytes_per_sector * sectors_per_cluster
    fat_start = partition_offset + reserved_sectors * bytes_per_sector
    fat_size_bytes = fat_size_sectors * bytes_per_sector
    data_start = fat_start + num_fats * fat_size_bytes
    if data_start >= partition_offset + partition_size:
        return None

    num_entries = fat_size_bytes // 4
    if num_entries < 3:
        return None

    return FAT32Layout(
        partition_offset=partition_offset,
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=sectors_per_cluster,
        cluster_size=cluster_size,
        fat_start=fat_start,
        fat_size_bytes=fat_size_bytes,
        data_start=data_start,
        num_entries=num_entries,
    )


def _clusters_to_regions(
    layout: FAT32Layout,
    free_clusters: list[int],
    partition_end: int,
) -> list[tuple[int, int]]:
    if not free_clusters:
        return []

    regions: list[tuple[int, int]] = []
    run_start = free_clusters[0]
    previous = free_clusters[0]

    for cluster in free_clusters[1:] + [-1]:
        if cluster == previous + 1:
            previous = cluster
            continue

        start_byte = layout.data_start + (run_start - 2) * layout.cluster_size
        run_clusters = previous - run_start + 1
        size_bytes = run_clusters * layout.cluster_size
        end_byte = min(start_byte + size_bytes, partition_end)
        if end_byte > start_byte:
            regions.append((start_byte, end_byte - start_byte))

        if cluster == -1:
            break
        run_start = cluster
        previous = cluster

    return regions


def _clip_regions(
    regions: list[tuple[int, int]],
    scan_start: int,
    scan_end: int,
) -> list[tuple[int, int]]:
    clipped: list[tuple[int, int]] = []
    for start, size in regions:
        end = start + size
        clip_start = max(start, scan_start)
        clip_end = min(end, scan_end)
        if clip_end > clip_start:
            clipped.append((clip_start, clip_end - clip_start))
    return clipped


def _category_for_extension(ext_clean: str) -> FileCategory:
    for category, extensions in CATEGORY_EXTENSIONS.items():
        if ext_clean in extensions:
            return category
    return FileCategory.OTHER
