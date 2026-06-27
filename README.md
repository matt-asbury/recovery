# Recovery

[![CI](https://github.com/matt-asbury/recovery/actions/workflows/ci.yml/badge.svg)](https://github.com/matt-asbury/recovery/actions/workflows/ci.yml)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm%20Noncommercial-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

A macOS disk recovery tool that scans attached volumes (including damaged or unmounted disks) using file carving, lists recoverable files, and exports them to another drive.
## Features

- **Volume discovery** — lists external and internal disks/partitions via `diskutil`
- **Deep scan** — raw block read with signature-based file carving (JPEG, PNG, GIF, PDF, MP4, MOV, AVI, DOC/XLS, DOCX/ZIP, RTF, HTML, MP3, and more)
- **Quick scan** — walks a mounted volume’s existing file tree (useful when the filesystem is still readable)
- **Web UI** — browser-based interface (no Tkinter required; avoids macOS Tcl/Tk version crashes)
- **Image previews** — thumbnail preview for carved images (JPEG, PNG, GIF, BMP, TIFF)
- **Scan ETA** — estimated time remaining during deep scans
- **Disk image mode** — scan `.img`, `.dmg`, or `.raw` files without touching the live device
- **CLI** — scriptable scanning and recovery for automation

## Requirements

- macOS
- Python 3.10+
- **Administrator access** for deep/raw scans (`sudo`)

Deep scans read from `/dev/rdisk*`, which requires root on macOS. Disk images can be scanned without sudo. The tool never writes to the source disk.

## Install

```bash
git clone https://github.com/matt-asbury/recovery.git
cd recovery
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
pytest
```

## Usage

### Web UI (recommended)

```bash
sudo ./recovery.sh
```

This opens a local web interface at `http://127.0.0.1:8765`. The UI runs in your browser and does not use Tkinter, so it avoids the common macOS error `macOS 15 (1507) or later required` caused by Xcode's bundled Tcl/Tk.

1. Select a volume from the list, or enter a path and click **Load Image**
2. Choose **Deep scan** (damaged/unmounted) or **Quick scan** (mounted & readable)
3. Click **Start Scan** — progress shows percent, ETA, and files found
4. Review found files, click a row to preview images, filter by type, and check files to recover
5. Click **Choose…** to pick a destination folder
6. Click **Recover Selected**

### CLI

List volumes:

```bash
python -m recovery --list
```

Deep scan a partition:

```bash
sudo python -m recovery --no-gui --device disk2s1
```

Scan and recover in one step:

```bash
sudo python -m recovery --no-gui --device disk2s1 --recover-to /Volumes/BackupDrive/Recovered
```

Quick scan a mounted volume:

```bash
python -m recovery --no-gui --device disk2s1 --quick
```

Scan a disk image (no sudo required):

```bash
./recovery.sh --no-gui --image ~/disk.img --recover-to ~/RecoveredFiles
```

Or from the UI, enter the image path and click **Load Image** after creating an image with:

```bash
sudo dd if=/dev/rdiskN of=~/disk.img bs=4m status=progress
```

## How it works

**Deep scan** opens the raw device read-only and scans in 4 MB chunks, searching for known file signatures (magic bytes). When a match is found, the tool estimates file boundaries (e.g. JPEG end marker, PNG `IEND` chunk, PDF `%%EOF`) and records offset, size, and type.

**Recovery** reads bytes from the source device at the recorded offset and writes them to the destination folder. Filenames are generated as `recovered_<offset>.<ext>` since original names are usually lost on damaged media.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, testing, and pull request guidelines.

```bash
pytest
sudo ./recovery.sh   # manual UI testing
```

## Troubleshooting

### `macOS 15 (1507) or later required, have instead 15 (1506)`

This comes from Apple's Xcode Python bundled with an outdated Tcl/Tk. Recovery uses a **browser UI** instead of Tkinter, so `./recovery.sh` should work without that error.

### Tkinter / IDLE issues on macOS

If you need Tkinter for other projects, install Python from [python.org](https://www.python.org/downloads/macos/) or Homebrew with a modern `tcl-tk`, rather than using `xcrun python3`.

## Limitations

This is a **basic** recovery tool, not a replacement for professional software (PhotoRec, Disk Drill, R-Studio, etc.):

- No filesystem repair or partition reconstruction
- Carved files may be truncated or corrupted if boundaries cannot be determined
- Duplicate and false-positive matches are possible
- Very large disks can take a long time to scan
- Encrypted volumes (FileVault, APFS encrypted) cannot be carved meaningfully without keys

## Safety

- Always recover **to a different drive** than the source
- Stop using a failing drive as soon as possible to avoid overwriting data
- For critical data, consider imaging the disk first: `sudo dd if=/dev/rdiskN of=~/disk.img bs=4m`

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

You may use, modify, and share this software for **noncommercial purposes** — for example personal recovery work, research, education, or use by nonprofits and government institutions.

**Commercial use is not permitted.** You may not sell this software, sell access to it, or sell products or services that are primarily based on it (including modified or derivative versions).

See the [license text](LICENSE) and https://polyformproject.org/licenses/noncommercial/1.0.0 for full terms.
