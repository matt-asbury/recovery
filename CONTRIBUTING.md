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
pytest
```

Most tests are unit tests and do not require root access or attached disks.

## Making changes

1. Fork the repository and create a branch from `main`.
2. Make focused changes with clear commit messages.
3. Add or update tests when behavior changes.
4. Run `pytest` before opening a pull request.
5. Open a PR using the provided template.

## Project layout

| Path | Purpose |
|------|---------|
| `recovery/scanner.py` | Deep and quick scan engines |
| `recovery/signatures.py` | File type detection |
| `recovery/webui.py` | Browser UI and HTTP API |
| `recovery/recover.py` | Export/carve recovered files |
| `recovery/preview.py` | Image preview generation |
| `tests/` | Unit tests |

## Coding guidelines

- Match existing style and naming in the file you edit.
- Keep changes scoped to the task.
- Prefer stdlib over new dependencies — this tool intentionally has zero runtime dependencies.
- Never write to source disks; recovery must remain read-only on scanned media.

## Reporting issues

Use the GitHub issue templates for bugs and feature requests. Include macOS version, Python version, and whether you were using `sudo`.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
