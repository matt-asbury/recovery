from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from recovery.filesystem import fat32_unallocated_regions, walk_filesystem
from recovery.hybrid import HybridScanner
from recovery.models import FileCategory, FoundFile
from recovery.scanner import DeepScanner
from recovery.volumes import volume_from_image

SECTOR = 512


def _minimal_valid_jpeg() -> bytes:
    data = b"\xff\xd8"
    jfif = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    data += b"\xff\xe0" + (len(jfif) + 2).to_bytes(2, "big") + jfif
    sof = b"\x08\x00\x10\x00\x10\x01\x01\x00\x00"
    data += b"\xff\xc0" + (len(sof) + 2).to_bytes(2, "big") + sof
    data += bytes((index * 7 + 13) % 256 for index in range(900))
    data += b"\xff\xd9"
    return data


def _write_fat32_image(path: Path, *, free_clusters: list[int], payload: bytes, payload_cluster: int) -> None:
    reserved_sectors = 32
    fat_size_sectors = 9
    num_fats = 2
    sectors_per_cluster = 1
    total_sectors = 512
    image = bytearray(SECTOR * total_sectors)

    image[0x52:0x5A] = b"FAT32   "
    struct.pack_into("<H", image, 0x0B, SECTOR)
    image[0x0D] = sectors_per_cluster
    struct.pack_into("<H", image, 0x0E, reserved_sectors)
    image[0x10] = num_fats
    struct.pack_into("<I", image, 0x24, fat_size_sectors)

    fat_start = reserved_sectors * SECTOR
    struct.pack_into("<I", image, fat_start + 0 * 4, 0x0FFFFFF8)
    struct.pack_into("<I", image, fat_start + 1 * 4, 0xFFFFFFFF)
    struct.pack_into("<I", image, fat_start + 2 * 4, 0x0FFFFFF8)
    for cluster in free_clusters:
        struct.pack_into("<I", image, fat_start + cluster * 4, 0x00000000)

    data_start = (reserved_sectors + num_fats * fat_size_sectors) * SECTOR
    cluster_size = SECTOR * sectors_per_cluster
    max_cluster = 1 + ((SECTOR * total_sectors - data_start) // cluster_size)
    for cluster in range(2, max_cluster + 1):
        if cluster in free_clusters or cluster == 2:
            continue
        struct.pack_into("<I", image, fat_start + cluster * 4, 0x0FFFFFF8)

    offset = data_start + (payload_cluster - 2) * cluster_size
    image[offset : offset + len(payload)] = payload
    path.write_bytes(image)


def test_walk_filesystem_uses_original_filename() -> None:
    with tempfile.TemporaryDirectory() as mount:
        photo = Path(mount) / "vacation.jpg"
        photo.write_bytes(b"fake-jpeg")
        found = walk_filesystem(mount)
        assert len(found) == 1
        assert found[0].filename == "vacation.jpg"
        assert found[0].source_kind == "filesystem"
        assert found[0].signature_name == "Filesystem"


def test_fat32_unallocated_regions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fat32.img"
        _write_fat32_image(path, free_clusters=[3, 4], payload=b"", payload_cluster=3)
        regions = fat32_unallocated_regions(str(path), partition_offset=0, partition_size=path.stat().st_size)
        assert regions is not None
        assert len(regions) == 1
        _start, size = regions[0]
        assert size == 2 * SECTOR


def test_hybrid_carves_only_unallocated_fat32_region() -> None:
    jpeg = _minimal_valid_jpeg()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fat32.img"
        _write_fat32_image(path, free_clusters=[3, 4], payload=jpeg, payload_cluster=3)

        volume = volume_from_image(str(path))
        scanner = HybridScanner(volume)
        carved: list[FoundFile] = []
        scanner.start(on_file=carved.append)
        scanner.join()

        assert scanner.progress.status.value == "complete"
        assert len(carved) >= 1
        assert carved[0].source_kind == "carved"
        assert carved[0].category == FileCategory.IMAGE


def test_deep_scanner_carve_regions_limits_scan() -> None:
    jpeg = _minimal_valid_jpeg()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "disk.img"
        image = bytearray(SECTOR * 128)
        carve_start = SECTOR * 40
        image[carve_start : carve_start + len(jpeg)] = jpeg
        path.write_bytes(image)

        volume = volume_from_image(str(path))
        scanner = DeepScanner(volume, carve_regions=[(carve_start, SECTOR * 4)])
        found: list[FoundFile] = []
        scanner.start(on_file=found.append)
        scanner.join()
        assert len(found) >= 1
        assert scanner.progress.total_bytes == SECTOR * 4
