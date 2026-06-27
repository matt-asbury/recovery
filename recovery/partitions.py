from __future__ import annotations

import struct

from recovery.device_io import read_bytes, SECTOR_SIZE
from recovery.models import PartitionInfo

GPT_SIGNATURE = b"EFI PART"
APM_SIGNATURE = b"PM"
MBR_BOOT_SIGNATURE = b"\x55\xAA"

# GPT type GUIDs (uppercase string form).
GPT_TYPE_LABELS = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "48465300-0000-11AA-AA1100306543ECAC": "Apple HFS+",
    "7C3457EF-04A0-11DB-9600-00306543ECAC": "Apple APFS",
    "52414944-0000-11AA-AA1100306543ECAC": "Apple RAID",
    "426F6F74-0000-11AA-AA1100306543ECAC": "Apple Boot",
    "53746F72-0000-11AA-AA1100306543ECAC": "Apple Core Storage",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "0657FD6D-A4AB-43C4-84E5-0933C84777BE": "Linux swap",
    "21686148-6449-6E6F-744E-65ED-00A0C93EC93B": "BIOS Boot",
}

MBR_TYPE_LABELS = {
    0x07: "NTFS/exFAT",
    0x0B: "FAT32",
    0x0C: "FAT32 LBA",
    0x0E: "FAT16 LBA",
    0x06: "FAT16",
    0x82: "Linux swap",
    0x83: "Linux",
    0xAF: "Apple HFS/HFS+",
    0xEE: "GPT Protective",
    0xEF: "EFI System",
}


def parse_partitions(
    path: str,
    media_size: int,
    *,
    sector_size: int = SECTOR_SIZE,
) -> list[PartitionInfo]:
    """Detect and parse GPT, Apple Partition Map, or MBR layouts."""
    if media_size <= 0:
        return []

    probe_size = min(media_size, sector_size * 64)
    probe = read_bytes(path, 0, probe_size)
    if len(probe) < sector_size * 2:
        return []

    if _is_gpt(probe, sector_size):
        return _parse_gpt(path, media_size, sector_size)
    if _is_apm(probe, sector_size):
        return _parse_apm(path, media_size, sector_size)
    if _is_mbr(probe):
        return _parse_mbr(probe, media_size, sector_size)
    return []


def _is_gpt(probe: bytes, sector_size: int) -> bool:
    header_offset = sector_size
    return probe[header_offset : header_offset + 8] == GPT_SIGNATURE


def _is_apm(probe: bytes, sector_size: int) -> bool:
    block = probe[sector_size : sector_size * 2]
    return len(block) >= 2 and block[:2] == APM_SIGNATURE


def _is_mbr(probe: bytes) -> bool:
    if len(probe) < 512:
        return False
    if probe[510:512] != MBR_BOOT_SIGNATURE:
        return False
    for index in range(4):
        entry_offset = 0x1BE + index * 16
        entry = probe[entry_offset : entry_offset + 16]
        if entry[4] != 0:
            return True
    return False


def _parse_gpt(path: str, media_size: int, sector_size: int) -> list[PartitionInfo]:
    header = read_bytes(path, sector_size, sector_size)
    if len(header) < 92 or header[:8] != GPT_SIGNATURE:
        return []

    entry_lba = struct.unpack("<Q", header[72:80])[0]
    entry_count = struct.unpack("<I", header[80:84])[0]
    entry_size = struct.unpack("<I", header[84:88])[0]
    if entry_count <= 0 or entry_size < 128:
        return []

    array_offset = entry_lba * sector_size
    array_size = entry_count * entry_size
    if array_offset + array_size > media_size:
        array_size = max(0, media_size - array_offset)
    array_data = read_bytes(path, array_offset, array_size)

    partitions: list[PartitionInfo] = []
    for index in range(entry_count):
        start = index * entry_size
        entry = array_data[start : start + entry_size]
        if len(entry) < 128:
            break

        type_guid = _format_guid(entry[0:16])
        if not type_guid:
            continue

        first_lba = struct.unpack("<Q", entry[32:40])[0]
        last_lba = struct.unpack("<Q", entry[40:48])[0]
        if last_lba < first_lba:
            continue

        start_byte = first_lba * sector_size
        size_bytes = (last_lba - first_lba + 1) * sector_size
        if start_byte >= media_size or size_bytes <= 0:
            continue
        size_bytes = min(size_bytes, media_size - start_byte)

        name = _decode_utf16le(entry[56:128])
        type_label = GPT_TYPE_LABELS.get(type_guid, f"GPT ({type_guid[:8]}…)")
        partitions.append(
            PartitionInfo(
                index=len(partitions),
                start_byte=start_byte,
                size_bytes=size_bytes,
                type_label=type_label,
                name=name,
                scheme="gpt",
            )
        )
    return partitions


def _parse_mbr(probe: bytes, media_size: int, sector_size: int) -> list[PartitionInfo]:
    partitions: list[PartitionInfo] = []
    for slot in range(4):
        entry_offset = 0x1BE + slot * 16
        entry = probe[entry_offset : entry_offset + 16]
        part_type = entry[4]
        if part_type == 0:
            continue
        if part_type == 0xEE:
            # Protective MBR for GPT — actual layout handled elsewhere.
            continue

        lba_start = struct.unpack("<I", entry[8:12])[0]
        sector_count = struct.unpack("<I", entry[12:16])[0]
        if sector_count == 0:
            continue

        start_byte = lba_start * sector_size
        size_bytes = sector_count * sector_size
        if start_byte >= media_size:
            continue
        size_bytes = min(size_bytes, media_size - start_byte)

        type_label = MBR_TYPE_LABELS.get(part_type, f"MBR type 0x{part_type:02x}")
        partitions.append(
            PartitionInfo(
                index=len(partitions),
                start_byte=start_byte,
                size_bytes=size_bytes,
                type_label=type_label,
                scheme="mbr",
            )
        )
    return partitions


def _parse_apm(path: str, media_size: int, sector_size: int) -> list[PartitionInfo]:
    header = read_bytes(path, sector_size, sector_size)
    if len(header) < 0x50 or header[:2] != APM_SIGNATURE:
        return []

    map_entries = struct.unpack(">I", header[4:8])[0]
    if map_entries <= 0 or map_entries > 128:
        return []

    partitions: list[PartitionInfo] = []
    for block_number in range(1, map_entries + 1):
        offset = block_number * sector_size
        if offset + sector_size > media_size:
            break
        entry = read_bytes(path, offset, sector_size)
        if len(entry) < 0x50 or entry[:2] != APM_SIGNATURE:
            continue

        start_block = struct.unpack(">I", entry[8:12])[0]
        block_count = struct.unpack(">I", entry[12:16])[0]
        if block_count == 0:
            continue

        name = _decode_pascal(entry[0x10:0x30])
        part_type = _decode_pascal(entry[0x30:0x50])
        start_byte = start_block * sector_size
        size_bytes = block_count * sector_size
        if start_byte >= media_size:
            continue
        size_bytes = min(size_bytes, media_size - start_byte)

        type_label = part_type or "Apple partition"
        if type_label.startswith("Apple_"):
            type_label = type_label.replace("_", " ", 1)

        partitions.append(
            PartitionInfo(
                index=len(partitions),
                start_byte=start_byte,
                size_bytes=size_bytes,
                type_label=type_label,
                name=name,
                scheme="apm",
            )
        )
    return partitions


def _format_guid(raw: bytes) -> str:
    if len(raw) != 16 or raw == b"\x00" * 16:
        return ""
    a = struct.unpack("<I", raw[0:4])[0]
    b = struct.unpack("<H", raw[4:6])[0]
    c = struct.unpack("<H", raw[6:8])[0]
    d = raw[8:10].hex().upper()
    e = raw[10:16].hex().upper()
    return f"{a:08X}-{b:04X}-{c:04X}-{d}-{e}"


def _decode_utf16le(raw: bytes) -> str:
    text = raw.split(b"\x00\x00", 1)[0]
    if len(text) % 2:
        text += b"\x00"
    try:
        return text.decode("utf-16-le").strip("\x00 ")
    except UnicodeDecodeError:
        return ""


def _decode_pascal(raw: bytes) -> str:
    if not raw:
        return ""
    length = raw[0]
    if length <= 0 or length >= len(raw):
        return ""
    try:
        return raw[1 : 1 + length].decode("mac_roman", errors="replace").strip()
    except Exception:
        return ""


def partition_to_dict(partition: PartitionInfo) -> dict[str, object]:
    return {
        "index": partition.index,
        "start_byte": partition.start_byte,
        "size_bytes": partition.size_bytes,
        "type_label": partition.type_label,
        "name": partition.name,
        "scheme": partition.scheme,
        "display_label": partition.display_label,
    }
