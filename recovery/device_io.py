from __future__ import annotations

import os
from typing import BinaryIO, Iterator

# macOS raw disk devices require sector-aligned I/O.
SECTOR_SIZE = 512


def is_raw_device(path: str) -> bool:
    """True for /dev/disk* and /dev/rdisk* character devices."""
    if not path.startswith("/dev/"):
        return False
    name = path[5:]
    return name.startswith("rdisk") or name.startswith("disk")


def read_bytes(path: str, offset: int, size: int) -> bytes:
    """Read bytes at an arbitrary offset, handling raw disk alignment."""
    if size <= 0:
        return b""

    if is_raw_device(path):
        return _read_raw_device(path, offset, size)

    with open(path, "rb") as handle:
        handle.seek(offset)
        data = handle.read(size)
    return data


def iter_bytes(path: str, offset: int, size: int, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
    """Yield bytes from offset..offset+size, aligned for raw devices."""
    if size <= 0:
        return

    if not is_raw_device(path):
        with open(path, "rb") as handle:
            handle.seek(offset)
            remaining = size
            while remaining > 0:
                chunk = handle.read(min(chunk_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk
        return

    remaining = size
    position = offset
    with open(path, "rb", buffering=0) as handle:
        while remaining > 0:
            chunk = _read_raw_device_from(handle, position, min(chunk_size, remaining))
            if not chunk:
                break
            yield chunk
            position += len(chunk)
            remaining -= len(chunk)


def write_bytes(path: str, offset: int, size: int, dest: BinaryIO) -> int:
    """Copy size bytes from path@offset to dest. Returns bytes written."""
    written = 0
    for chunk in iter_bytes(path, offset, size):
        dest.write(chunk)
        written += len(chunk)
    return written


def _read_raw_device(path: str, offset: int, size: int) -> bytes:
    with open(path, "rb", buffering=0) as handle:
        return _read_raw_device_from(handle, offset, size)


def _read_raw_device_from(handle: BinaryIO, offset: int, size: int) -> bytes:
    aligned_offset = offset - (offset % SECTOR_SIZE)
    leading_skip = offset - aligned_offset
    read_size = leading_skip + size
    read_size = _align_up(read_size, SECTOR_SIZE)

    handle.seek(aligned_offset)
    data = handle.read(read_size)
    if len(data) <= leading_skip:
        return b""
    return data[leading_skip : leading_skip + size]


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment
