# Contributing to Recovery

Thanks for your interest in contributing. This project is a macOS-focused disk recovery tool with a browser UI and CLI.

## Getting started

### Prerequisites

- macOS
- Python 3.10+
- Git

### Development setup

```bash
git clone https://github.com/matt-asbury/recovery.git
cd recovery
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run the app locally

```bash
sudo ./recovery.sh
```

Deep scans of raw devices require `sudo`. Disk image scans do not.

### Run tests

```bash
# Fast unit tests (default in CI, with coverage)
pytest -m unit --cov=recovery

# Slower integration tests (HTTP API, scanner on disk images)
pytest -m integration

# Everything
pytest
```

Most tests are unit tests and do not require root access or attached disks.

## Test pyramid

We follow a classic test pyramid: many fast unit tests at the base, fewer integration tests above, and no automated end-to-end UI tests yet.

| Layer | Location | Marker | What it covers |
| ----- | -------- | ------ | -------------- |
| Unit | `tests/test_*.py` (except `tests/integration/`) | `unit` | Pure logic: models, validation, security helpers, results store, preview parsing |
| Integration | `tests/integration/` | `integration` | HTTP handler smoke tests, scanner against synthetic disk images |
| Manual | — | — | Real device scans, browser UI, `sudo ./recovery.sh` |

Guidelines:

- Put new behavior in **unit tests first** when the code under test has no I/O.
- Add an **integration test** when wiring crosses modules (e.g. scanner → validation → results).
- Keep integration tests **deterministic** — use temp files and synthetic images, not attached disks.
- CI runs unit tests on Python 3.10 and 3.12, then integration tests and a full-suite coverage gate (`--cov-fail-under=40`) on 3.12.

## Making changes

1. Fork the repository and create a branch from `main`.
2. Make focused changes with clear commit messages.
3. Add or update tests when behavior changes.
4. Run `pytest` before opening a pull request.
5. Open a PR using the provided template.

## Project layout

| Path | Purpose |
|------|---------|
| `recovery/partitions.py` | GPT/MBR/APM partition table parsing |
| `recovery/scanner.py` | Deep and quick scan engines |
| `recovery/signatures.py` | File type detection |
| `recovery/webui.py` | Browser UI and HTTP API |
| `recovery/recover.py` | Export/carve recovered files |
| `recovery/preview.py` | Image preview generation |
| `recovery/security.py` | Path validation and localhost checks |
| `tests/` | Unit and integration tests |

## Coding guidelines

- Match existing style and naming in the file you edit.
- Keep changes scoped to the task.
- Prefer stdlib over new dependencies — this tool intentionally has zero runtime dependencies.
- Never write to source disks; recovery must remain read-only on scanned media.

## Reporting issues

Use the GitHub issue templates for bugs and feature requests. Include macOS version, Python version, and whether you were using `sudo`.

## License

By contributing, you agree that your contributions will be licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
