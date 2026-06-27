# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Carved-file validation pipeline with confidence scoring during deep scans.
- Confidence filter in the file list UI (default hides low-confidence hits).
- SQLite-backed results store for scalable scan result persistence.
- `recovery.security` module for path validation and localhost-only HTTP access.
- Test pyramid: unit vs integration markers, coverage in CI, security and recovery tests.
- Partition table parsing (GPT, MBR, Apple Partition Map) for disk images and whole disks.
- Partition-scoped deep scans in the UI, CLI (`--partition`), and scanner.
- Hybrid scan mode: filesystem walk plus carving of FAT32 unallocated space.
- Original filenames for filesystem-discovered files during hybrid/quick scans.
- Encryption detection for live volumes (FileVault/APFS) with scan-mode guidance.
- Redesigned web UI with workflow steps, volume cards, toasts, and static assets.
- Expandable scan activity log with live progress stats (rate, bytes, ETA, elapsed).
- Thumbnail grid view for image results with lazy-loaded previews.
- Step-by-step wizard UX: one stage visible at a time (source → scan → review → recover) with gated navigation.

### Changed
- Project license changed from PolyForm Noncommercial 1.0.0 to GNU General Public License v3.0.
- Quick scan now tags results as `filesystem` and shows basename filenames.
- Recovery export validates destination paths and rejects traversal in filenames.
- HTTP API rejects non-local clients and oversized JSON bodies.

## [0.1.0] - 2026-06-27

### Added
- Browser-based Web UI for volume selection, scanning, filtering, previews, and recovery.
- Deep scan with signature-based file carving from raw devices and disk images.
- Quick scan for mounted volumes.
- Image previews via macOS `sips`.
- Scan ETA and paginated results for large file sets.
- Timestamp extraction from carved file headers (EXIF, PDF, MP4, PNG, ZIP).
- Recovery progress modal with success confirmation.
- CLI for headless scanning and recovery.

[Unreleased]: https://github.com/matt-asbury/recovery/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/matt-asbury/recovery/releases/tag/v0.1.0
