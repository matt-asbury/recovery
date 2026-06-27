# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you discover a security issue, please **do not** open a public GitHub issue.

Instead, report it privately to the repository maintainers. Include:

- A description of the issue
- Steps to reproduce
- Potential impact
- Any suggested fix, if you have one

We aim to acknowledge reports within a few business days.

## Threat model

Recovery is a **local-first** macOS tool. The primary user runs it on their own machine to scan disks or disk images and write recovered files to a destination they choose.

### In scope

| Surface | Exposure | Notes |
| ------- | -------- | ----- |
| HTTP API (`webui.py`) | Loopback by default (`127.0.0.1`) | Binds locally; not intended for LAN or internet exposure |
| Raw disk / image reads | Requires user action + often `sudo` | Read-only on scanned media by design |
| Recovery writes | User-chosen destination directory | Must not escape destination or overwrite arbitrary paths |
| Disk image paths | User-supplied file paths | Must resolve to regular readable files, not devices or symlinks to sensitive targets |
| JSON request bodies | POST endpoints | Bounded size to limit memory use |

### Out of scope / accepted limitations

- **Physical access** — Anyone with shell access on the machine can already read disks and write files.
- **Malicious disk images** — Parsing carved content is best-effort; pathological inputs may cause high CPU or memory use during scan.
- **Browser same-origin policy** — The UI assumes a trusted local browser session on the same machine.
- **Non-macOS platforms** — Device enumeration and volume handling are macOS-specific and untested elsewhere.

## Controls

The `recovery.security` module centralizes path and request checks:

- **`is_local_client`** — Rejects non-loopback HTTP clients with HTTP 403.
- **`validate_recovery_destination`** — Ensures the recovery output path is (or will be) a directory, not a device special file.
- **`safe_filename` / `safe_destination_path`** — Rejects path traversal, separators, and paths that escape the destination directory.
- **`validate_readable_file_path`** — Resolves disk image paths to regular files via `realpath`.
- **`MAX_JSON_BODY_BYTES`** — Caps JSON POST bodies at 1 MiB.

Recovery export (`recover.py`) uses these helpers before every write.

## Residual risks

1. **Binding to `0.0.0.0`** — If started with a non-loopback host, the localhost check is the main network control. Prefer `127.0.0.1`.
2. **Symlinks in destination** — Existing symlink destinations are resolved with `realpath`; newly created paths follow the validated directory.
3. **Privilege escalation via `sudo`** — Deep scans require root; run only when needed and only on media you trust.
4. **No authentication** — Localhost binding is the access control; do not expose the port beyond the machine.

## Security-related changes

When changing scan, recovery, or HTTP behavior, add or update tests in `tests/test_security.py`, `tests/test_recover.py`, or `tests/integration/`.
