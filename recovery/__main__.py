from __future__ import annotations

import argparse
import sys

from recovery.gui import run_gui
from recovery.models import ScanStatus
from recovery.recover import recover_files
from recovery.encryption import scan_mode_error
from recovery.hybrid import HybridScanner
from recovery.scanner import DeepScanner, quick_scan_mount
from recovery.volumes import list_volumes, volume_for_partition, volume_from_image


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mac disk recovery — deep scan damaged volumes and carve recoverable files.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List attached volumes and exit",
    )
    parser.add_argument(
        "--device",
        help="Device to scan, e.g. disk2s1 or /dev/disk2s1",
    )
    parser.add_argument(
        "--image",
        metavar="PATH",
        help="Scan a disk image file (.img, .dmg, .raw) instead of a live device",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan mounted files instead of deep raw scan",
    )
    parser.add_argument(
        "--hybrid",
        action="store_true",
        help="Hybrid scan: walk mounted filesystem then carve unallocated space",
    )
    parser.add_argument(
        "--recover-to",
        metavar="DIR",
        help="Recover all found files to this directory after scanning",
    )
    parser.add_argument(
        "--include-internal",
        action="store_true",
        help="Include internal/system disks when listing or selecting",
    )
    parser.add_argument(
        "--partition",
        type=int,
        default=-1,
        metavar="N",
        help="Partition index to scan (default: whole disk/image)",
    )
    parser.add_argument(
        "--no-gui",
        action="store_true",
        help="Use CLI mode (requires --device or --image for scanning)",
    )
    return parser


def normalize_device(device: str) -> str:
    device = device.strip()
    if device.startswith("/dev/"):
        return device
    return f"/dev/{device}"


def resolve_scan_target(args: argparse.Namespace):
    if args.image:
        return volume_from_image(args.image)

    if not args.device:
        return None

    device = normalize_device(args.device)
    volumes = list_volumes(include_internal=True)
    volume = next(
        (v for v in volumes if v.device_id == device or v.raw_device == device),
        None,
    )
    if volume is None:
        print(f"Unknown device: {device}", file=sys.stderr)
        raise SystemExit(1)
    return volume


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list:
        for vol in list_volumes(include_internal=args.include_internal):
            print(vol.display_name)
            for partition in vol.partitions:
                print(f"  [{partition.index}] {partition.display_label}")
        return 0

    if args.quick and args.hybrid:
        parser.error("Use either --quick or --hybrid, not both")

    if args.device and args.image:
        parser.error("Use either --device or --image, not both")

    if not args.no_gui and not args.device and not args.image:
        run_gui()
        return 0

    volume = resolve_scan_target(args)
    if volume is None:
        parser.error("--device or --image is required for CLI mode")

    try:
        volume = volume_for_partition(volume, args.partition)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.partition >= 0 and volume.partitions:
        part = volume.partitions[args.partition]
        print(f"Scanning partition {args.partition}: {part.display_label}")

    if volume.encryption.is_encrypted:
        print(f"Encryption: {volume.encryption.summary}")

    scan_mode = "quick" if args.quick else "hybrid" if args.hybrid else "deep"
    mode_error = scan_mode_error(volume, scan_mode)
    if mode_error:
        print(mode_error, file=sys.stderr)
        return 1

    found: list = []

    def on_progress(progress) -> None:
        if progress.status == ScanStatus.SCANNING:
            print(
                f"\r{progress.progress_summary}",
                end="",
                flush=True,
            )
        elif progress.status == ScanStatus.ERROR:
            print(f"\nError: {progress.error}", file=sys.stderr)

    if args.quick:
        if volume.is_disk_image:
            print("Quick scan is not supported for disk images.", file=sys.stderr)
            return 1
        if not volume.mount_point:
            print("Volume is not mounted; use deep or hybrid scan instead.", file=sys.stderr)
            return 1
        found = quick_scan_mount(volume.mount_point)
        print(f"Found {len(found)} file(s)")
        for item in found:
            print(f"  {item.filename}  {item.preview_note}  ({item.size_human})  {item.timestamp_display}")
    elif args.hybrid:
        scanner = HybridScanner(volume)

        def on_file(item) -> None:
            found.append(item)

        scanner.start(on_file=on_file, on_progress=on_progress)
        scanner.join()
        print(f"\n{scanner.progress.current_message}")
    else:
        scanner = DeepScanner(volume)
        scanner.start(on_progress=on_progress)
        scanner.join()
        found = scanner.results
        print(f"\nFound {len(found)} recoverable file(s)")

    if not args.quick:
        for item in found:
            if item.is_filesystem_file:
                print(
                    f"  {item.filename}  path={item.preview_note}  "
                    f"size={item.size_human}  created={item.timestamp_display}"
                )
            else:
                print(
                    f"  {item.filename}  offset=0x{item.offset:x}  "
                    f"size={item.size_human}  created={item.timestamp_display}  "
                    f"type={item.signature_name}"
                )

    if args.recover_to:
        target = args.recover_to
        to_recover = found
        results = recover_files(to_recover, target)
        ok = sum(1 for r in results if r.success)
        print(f"Recovered {ok}/{len(results)} file(s) to {target}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
