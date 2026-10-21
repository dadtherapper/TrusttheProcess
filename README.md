# Trust the Process - examining your process list

A read-only Windows process and network monitor with local history, behavioral baselines, and explainable findings.

## Run

Requires Python 3.11+ with Tkinter.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m trust_the_process
```

For synthetic demo data, add `--demo` to the launch command.

## Test

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
```

Data stays local. Optional reputation lookups are disabled by default. Findings are investigation leads, not malware verdicts; socket snapshots are not packet captures.

[Usage and building](docs/usage.md) · [Detection rules](docs/detection.md) · [Privacy and limitations](docs/security.md)

MIT licensed.
