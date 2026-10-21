"""Launch the console or run a finite read-only collection smoke check."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from . import __version__
from .config import Config, configure_logging, data_directory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trust the Process. Verify the Behavior.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--demo", action="store_true", help="isolated, clearly simulated telemetry")
    parser.add_argument(
        "--capture-demo",
        type=Path,
        help="render demo GUI screenshots to a directory without desktop interaction (Windows)",
    )
    parser.add_argument("--data-dir", type=Path, help="override the local data directory")
    parser.add_argument("--interval", type=float, help="sampling interval in seconds (1–300)")
    parser.add_argument(
        "--headless", action="store_true", help="finite pipeline check without a GUI"
    )
    parser.add_argument("--cycles", type=int, default=3, help="headless observation count")
    parser.add_argument("--export", type=Path, help="headless redacted JSON report destination")
    args = parser.parse_args(argv)
    if args.cycles < 1:
        parser.error("--cycles must be positive")
    if args.export and not args.headless:
        parser.error("--export is supported with --headless")
    if args.capture_demo:
        if not args.demo or args.headless or args.export:
            parser.error(
                "--capture-demo requires --demo and cannot be combined with --headless/--export"
            )
        if os.name != "nt":
            parser.error("--capture-demo requires Windows")
        from .demo_capture import main as capture_main

        capture_main(["--output", str(args.capture_demo)])
        return 0
    folder = args.data_dir or data_directory(args.demo)
    try:
        config = Config.load(folder / "config.json")
        if args.interval is not None:
            config.interval = args.interval
        if args.demo:
            config.abuseipdb_enabled = config.virustotal_enabled = False
            if args.interval is None:
                config.interval = 1.0
        config.validate()
        configure_logging(folder)
    except (ValueError, TypeError, OSError) as error:
        parser.exit(
            2,
            f"Configuration could not be loaded: {error}. Check {folder / 'config.json'}.\n",
        )
    if args.headless:
        from .collector import HostCollector
        from .demo import DemoCollector
        from .engine import Engine
        from .storage import Store

        database = folder / (f"session-{time.time_ns()}.db" if args.demo else "history.db")
        try:
            with ExitStack() as cleanup:
                store = Store(database)
                cleanup.callback(store.close)
                collector = DemoCollector(config.min_samples) if args.demo else HostCollector()
                cleanup.callback(collector.close)
                engine = Engine(config, store, collector)
                cleanup.callback(engine.persist)
                for index in range(args.cycles):
                    state = engine.cycle(persist=True)
                    if index < args.cycles - 1 and not args.demo:
                        time.sleep(config.interval)
                if args.export:
                    engine.export(args.export, "json", redacted=True)
                print(
                    json.dumps(
                        {
                            "simulated": args.demo,
                            "cycles": args.cycles,
                            "processes": len(state.snapshot.processes),
                            "connections": len(state.snapshot.connections),
                            "network_available": state.snapshot.network_available,
                            "findings": len(state.findings),
                            "rules": sorted({f["rule_id"] for f in state.findings}),
                            "baselines": len(engine.baselines.state),
                            "source": state.snapshot.source,
                        }
                    )
                )
        except KeyboardInterrupt:
            return 130
        except (ValueError, OSError, sqlite3.Error) as error:
            parser.exit(
                2,
                f"Monitoring failed ({type(error).__name__}). Check data access and report destination.\n",
            )
        return 0
    import tkinter as tk

    from .gui import Application

    try:
        root = tk.Tk()
    except tk.TclError:
        print(
            "Tk could not open a display. Install Python with Tcl/Tk support and use a desktop session.",
            file=sys.stderr,
        )
        return 2
    application = Application(root, config, folder, args.demo)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        return 130
    finally:
        application.monitor.shutdown()
        application.monitor.thread.join()
        try:
            root.destroy()
        except tk.TclError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
