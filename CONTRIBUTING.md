# Contributing

Install with `python -m pip install -e ".[dev]"`. Run `python -m pytest -q`, `python -m ruff check .`, and `python -m ruff format --check .` before submitting changes. For interface changes run `python scripts/gui_smoke.py` in a desktop session and inspect each view at the minimum window size and your Windows scaling setting.

Keep collection, detection, persistence, and UI separate. All widgets belong on Tk's main thread. Treat access denial and terminated processes as normal inputs; preserve missing metrics and process lifetimes. Detection rules need supporting evidence, documented thresholds/weights, sample requirements where appropriate, and tests for benign/insufficient/missing cases. Any new telemetry source must describe its actual capabilities without implying packet, kernel, or historical visibility it does not provide.

Use mocked HTTP in tests. Do not introduce automatic uploads or silently enable providers. Never commit API keys, real telemetry, databases, generated executables, or personal screenshots. Include privacy/attribution considerations in report changes, version breaking report contracts, and keep deterministic demo data clearly separated from live collection.
