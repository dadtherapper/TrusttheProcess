# Usage

Trust the Process runs on Python 3.11 or newer with Tcl/Tk. Windows 10/11 is the primary platform. The collection engine and unit tests also run on Linux; its GUI requires Tk and a graphical session.

## Monitoring

`python -m trust_the_process` starts local monitoring. Use Pause and Resume to control collection. Processes and Connections support search, column sorting, and filtering. Select a process for its identity, command line, resource usage, network activity, and baseline. Timeline opens retained observations; the relationship view shows verified ancestry and children. Findings show evidence, expectations, sources, and investigation suggestions. Acknowledgment records review without removing evidence.

A dash means unavailable, not zero. CPU can exceed 100% across cores. Hashing is asynchronous, cached by file metadata, and excludes unreadable, nonregular, network-path, and oversized (>512 MiB) files. First process sightings are saved immediately; full resource snapshots are saved about every 15 seconds, on pause, and at shutdown. A crash can lose recent samples. Collection adds time to the configured interval.

The process score combines distinct rule weights for the lifetime identified by PID and creation time. It is a triage aid, not a malware probability. All retained evidence contributes to scores. The Findings page filters and sorts the full retained history, showing 200 records per page. See [detection rules](detection.md).

## Demo and finite checks

```powershell
python -m trust_the_process --demo
python -m trust_the_process --demo --headless --cycles 36
python -m trust_the_process --headless --cycles 3 --interval 1
```

Demo mode uses separate synthetic process, socket, and reputation data through the real detection pipeline. It does not inspect the host or contact providers. At default settings, behavior changes around observation 25; resource findings follow after sustained samples. The public resolver addresses shown are synthetic endpoints, not real adverse reputation claims. Demo logical timestamps advance three seconds per poll; the default GUI interval is one wall-clock second.

## Settings and data

Settings controls polling, retention, detection thresholds, and baseline reset/inspection. Local data defaults to `%LOCALAPPDATA%\TrustTheProcess\live`, with separate demo sessions under `demo`. `--data-dir PATH` overrides the directory. Keep real telemetry outside repositories and shared folders.

`config.example.json` contains all supported non-secret preferences. Save Settings to create the local `config.json`, or copy the example there while the app is closed. The default baseline needs 20 polls with available metrics and uses a rolling 120-sample window. Retention is 14 days with hard row caps; busy hosts may retain less. Inactive executable baselines expire too. Reset preserves investigation history. Close the app before deleting local history.

## Optional reputation

Keys are read only from environment variables:

```powershell
$env:TTP_ABUSEIPDB_API_KEY = "your-own-key"
$env:TTP_VIRUSTOTAL_API_KEY = "your-own-key"
python -m trust_the_process
```

Enable a provider in Settings and save. In Connections, choose a selected public IP or paste a public IP/SHA-256, then click Look up. Enabling a provider alone sends nothing. AbuseIPDB supports IPs only. No files, packet payloads, commands, or usernames are sent. Providers receive the selected indicator and your source IP; VirusTotal may add queried indicators to its dataset. Review the [provider terms and privacy details](security.md). An absent or neutral report does not establish safety.

## Export

Export findings as JSON/CSV, or export a process investigation from Processes or its timeline. Redaction is enabled by default and removes identifying fields and free text, including duplicated values in evidence. Review reports before sharing. Never publish real telemetry or keys. See the [report schema](report-schema.md).

## Development and Windows build

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python scripts/gui_smoke.py
python -m PyInstaller --noconfirm packaging/TrustTheProcess.spec
```

Build on Windows and distribute the entire `dist\TrustTheProcess` folder. The executable is unsigned and requests no elevation. The manually dispatched Windows build workflow tests, builds, and uploads an artifact; it does not publish a release. For opt-in host validation, `python scripts/live_smoke.py` uses an isolated temporary database and prints aggregate counts only.

On Windows, `python scripts/capture_demo.py --output PATH` captures the real synthetic GUI without desktop interaction. Its output is generated material and should stay outside the source tree. `python scripts/gui_smoke.py --exe dist/TrustTheProcess/TrustTheProcess.exe` checks the packaged pipeline and rendering too.

## Limits

This is read-only investigation software. Socket snapshots can miss brief activity, attribution is best effort, and permissions can hide fields. It does not capture packets, measure per-process byte volume, ingest Sysmon, verify signatures, scan process memory, terminate processes, or quarantine files. It has no historical visibility before observation and provides no guarantee that an unflagged process is safe.
