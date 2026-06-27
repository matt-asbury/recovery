from __future__ import annotations

import struct
import tempfile
import uuid
from pathlib import Path

from recovery.models import PartitionInfo, VolumeInfo
from recovery.partitions import parse_partitions
from recovery.scanner import DeepScanner
from recovery.volumes import volume_for_partition, volume_from_image

SECTOR = 512
APFS_GUID = "7C3457EF-04A0-11DB-9600-00306543ECAC"
EFI_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def _guid_bytes(value: str) -> bytes:
    return uuid.UUID(value).bytes_le


def _minimal_valid_jpeg() -> bytes:
    data = b"\xff\xd8"
    jfif = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    data += b"\xff\xe0" + (len(jfif) + 2).to_bytes(2, "big") + jfif
    sof = b"\x08\x00\x10\x00\x10\x01\x01\x00\x00"
    data += b"\xff\xc0" + (len(sof) + 2).to_bytes(2, "big") + sof
    data += bytes((index * 7 + 13) % 256 for index in range(900))
    data += b"\xff\xd9"
    return data


def _write_gpt_image(
    path: Path,
    *,
    partitions: list[tuple[str, str, int, int]],
) -> None:
    """Build a minimal GPT image with named partitions."""
    total_sectors = 256
    image = bytearray(SECTOR * total_sectors)

    image[510:512] = b"\x55\xAA"
    image[0x1BE + 4] = 0xEE

    header = SECTOR
    image[header : header + 8] = b"EFI PART"
    struct.pack_into("<I", image, header + 72, 2)
    struct.pack_into("<I", image, header + 80, len(partitions))
    struct.pack_into("<I", image, header + 84, 128)

    for index, (type_guid, name, first_lba, last_lba) in enumerate(partitions):
        entry = SECTOR * 2 + index * 128
        image[entry : entry + 16] = _guid_bytes(type_guid)
        struct.pack_into("<Q", image, entry + 32, first_lba)
        struct.pack_into("<Q", image, entry + 40, last_lba)
        encoded = name.encode("utf-16-le")
        image[entry + 56 : entry + 56 + len(encoded)] = encoded

    path.write_bytes(image)


def _write_mbr_image(path: Path) -> None:
    image = bytearray(SECTOR * 128)
    image[510:512] = b"\x55\xAA"
    entry = 0x1BE
    image[entry + 4] = 0x07
    struct.pack_into("<I", image, entry + 8, 64)
    struct.pack_into("<I", image, entry + 12, 32)
    path.write_bytes(image)


def _write_apm_image(path: Path) -> None:
    image = bytearray(SECTOR * 128)

    def write_entry(block: int, name: str, part_type: str, start: int, count: int, total: int) -> None:
        offset = block * SECTOR
        image[offset : offset + 2] = b"PM"
        struct.pack_into(">I", image, offset + 4, total)
        struct.pack_into(">I", image, offset + 8, start)
        struct.pack_into(">I", image, offset + 12, count)
        name_bytes = name.encode("mac_roman")
        image[offset + 16] = len(name_bytes)
        image[offset + 17 : offset + 17 + len(name_bytes)] = name_bytes
        type_bytes = part_type.encode("mac_roman")
        image[offset + 0x30] = len(type_bytes)
        image[offset + 0x31 : offset + 0x31 + len(type_bytes)] = type_bytes

    write_entry(1, "Apple", "Apple_partition_map", 1, 127, 2)
    write_entry(2, "Data", "Apple_HFS", 8, 32, 2)
    path.write_bytes(image)


def test_parse_gpt_partitions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "gpt.img"
        _write_gpt_image(
            path,
            partitions=[
                (EFI_GUID, "EFI System", 40, 239),
                (APFS_GUID, "Macintosh HD", 240, 20000),
            ],
        )
        partitions = parse_partitions(str(path), path.stat().st_size)
        assert len(partitions) == 2
        assert partitions[0].scheme == "gpt"
        assert partitions[0].type_label == "EFI System"
        assert partitions[1].type_label == "Apple APFS"
        assert partitions[1].start_byte == 240 * SECTOR


def test_parse_mbr_partitions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "mbr.img"
        _write_mbr_image(path)
        partitions = parse_partitions(str(path), path.stat().st_size)
        assert len(partitions) == 1
        assert partitions[0].scheme == "mbr"
        assert partitions[0].start_byte == 64 * SECTOR
        assert partitions[0].size_bytes == 32 * SECTOR


def test_parse_apm_partitions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "apm.img"
        _write_apm_image(path)
        partitions = parse_partitions(str(path), path.stat().st_size)
        assert len(partitions) == 2
        assert partitions[0].scheme == "apm"
        assert partitions[1].type_label == "Apple HFS"


def test_volume_from_image_discovers_partitions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "gpt.img"
        _write_gpt_image(
            path,
            partitions=[(APFS_GUID, "Data", 64, 20000)],
        )
        volume = volume_from_image(str(path))
        assert len(volume.partitions) == 1
        assert volume.partitions[0].type_label == "Apple APFS"


def test_volume_for_partition_scopes_scan_region() -> None:
    volume = VolumeInfo(
        device_id="/tmp/test.img",
        name="test.img",
        size_bytes=SECTOR * 256,
        mount_point=None,
        file_system="disk_image",
        is_removable=True,
        is_internal=False,
        whole_disk=True,
        is_disk_image=True,
        image_path="/tmp/test.img",
        partitions=(
            PartitionInfo(
                index=0,
                start_byte=SECTOR * 64,
                size_bytes=SECTOR * 32,
                type_label="Apple APFS",
                scheme="gpt",
            ),
        ),
    )
    scoped = volume_for_partition(volume, 0)
    assert scoped.scan_start_byte == SECTOR * 64
    assert scoped.scan_size_bytes == SECTOR * 32
    assert scoped.is_partition_scan


def test_partition_scoped_scan_finds_jpeg() -> None:
    jpeg = _minimal_valid_jpeg()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "gpt.img"
        _write_gpt_image(
            path,
            partitions=[(APFS_GUID, "Data", 64, 20000)],
        )
        data = bytearray(path.read_bytes())
        part_start = 64 * SECTOR
        data[part_start : part_start + len(jpeg)] = jpeg
        path.write_bytes(data)

        volume = volume_for_partition(volume_from_image(str(path)), 0)
        scanner = DeepScanner(volume)
        found: list = []
        scanner.start(on_file=found.append)
        scanner.join()
        assert scanner.progress.status.value == "complete"
        assert len(found) >= 1
        assert found[0].offset == part_start
