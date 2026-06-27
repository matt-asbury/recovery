# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Carved-file validation pipeline with confidence scoring during deep scans.
- Confidence filter in the file list UI (default hides low-confidence hits).

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
