"""Opt-in, real Tk event-loop integration checks. Run from an interactive desktop.

No host telemetry or external providers are used. --exe verifies the bundled headless
pipeline; the ordinary invocation exercises the source GUI and clean shutdown.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ttp-gui-check-") as temporary:
        folder = Path(temporary)
        if args.exe:
            output = folder / "report.json"
            subprocess.run(
                [
                    str(args.exe.resolve()),
                    "--demo",
                    "--headless",
                    "--cycles",
                    "36",
                    "--data-dir",
                    str(folder),
                    "--export",
                    str(output),
                ],
                check=True,
                timeout=60,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            assert payload["simulated"] and payload["redacted"]
            assert {"RES-MEM", "TI-REPUTATION"} <= {f["rule_id"] for f in payload["findings"]}
            screenshots = folder / "screenshots"
            subprocess.run(
                [str(args.exe.resolve()), "--demo", "--capture-demo", str(screenshots)],
                check=True,
                timeout=60,
            )
            images = list(screenshots.glob("*.png"))
            assert len(images) == 7 and all(p.read_bytes().startswith(b"\x89PNG") for p in images)
            print("Packaged demo pipeline, GUI rendering, and report: passed")
            return
        import tkinter as tk

        from trust_the_process.config import Config
        from trust_the_process.gui import Application, Table

        root = tk.Tk()
        app = Application(root, Config(interval=1, min_samples=5), folder, demo=True)
        errors = []
        checks = []

        def failed(kind, value, traceback):
            errors.append(f"{kind.__name__}: {value}")
            app.close()

        root.report_callback_exception = failed

        def exercise():
            table = Table(root, [("value", "Value", 100)])
            table.update_rows([("same", (1,), "Low"), ("same", (1,), "Low")])
            assert len(table.tree.get_children()) == 1
            table.update_rows([("same", (1,), "Informational")])
            assert table.tree.item("same", "tags") == ("Informational",)
            table.destroy()
            assert app.state and len(app.state.snapshot.processes) == 5
            assert {"RES-MEM", "NET-FIRST", "TI-REPUTATION"} <= {
                f["rule_id"] for f in app.state.findings
            }
            for name in app.NAV:
                app.navigate(name)
                root.update_idletasks()
            app.navigate("Processes")
            app.search.set("renderer")
            assert len(app.process_table.tree.get_children()) == 1
            selected = app.process_table.tree.get_children()[0]
            app.process_table.tree.selection_set(selected)
            app.select_process()
            assert "BEHAVIORAL BASELINE" in app.process_detail.get("1.0", "end")
            app.process_relationships()
            root.update_idletasks()
            graph = next(
                w
                for w in root.winfo_children()
                if isinstance(w, tk.Toplevel) and w.title() == "Observed process relationships"
            )
            graph.destroy()
            root.geometry("1100x720")
            root.update_idletasks()
            assert app.process_detail.winfo_width() >= 200
            app.search.set("")
            app.process_table.sort(3)
            app.navigate("Connections")
            key = app.connection_table.tree.get_children()[0]
            app.connection_table.tree.selection_set(key)
            app.select_connection()
            assert app.indicator.get()
            app.navigate("Findings")
            original_findings = app.state.findings
            template = original_findings[0]
            app.state.findings = (
                original_findings
                + [{**template, "id": f"test-{i}", "severity": "Low"} for i in range(201)]
                + [
                    {
                        **template,
                        "id": "test-old-high",
                        "severity": "High",
                        "last_seen": "2000-01-01T00:00:00+00:00",
                    }
                ]
            )
            app.render_findings()
            assert len(app.finding_table.tree.get_children()) == 200
            app.change_finding_page(1)
            assert 0 < len(app.finding_table.tree.get_children()) < 200
            app.severity_filter.set("High")
            app.filter_findings()
            assert app.finding_table.tree.get_children() == ("test-old-high",)
            app.state.findings = original_findings
            app.severity_filter.set("All severities")
            app.filter_findings()
            key = app.finding_table.tree.get_children()[0]
            app.finding_table.tree.selection_set(key)
            app.select_finding()
            assert "EVIDENCE" in app.finding_detail.get("1.0", "end")
            app.acknowledge()
            app.settings_vars["interval"].set("2")
            app.save_settings()
            app.monitor.submit(
                "export",
                path=folder / "check.json",
                mode="investigation",
                redacted=True,
                process_key=selected,
            )
            app.pause()
            checks.extend(
                [
                    "navigation",
                    "search",
                    "sort",
                    "process inspection",
                    "socket inspection",
                    "finding evidence",
                    "acknowledgment",
                    "report export",
                    "pause",
                ]
            )
            root.after(1000, check_pause)

        def check_pause():
            assert app.monitor.paused.is_set()
            assert (folder / "check.json").exists()
            assert any(f["acknowledged"] for f in app.state.findings)
            assert app.config.interval == app.monitor.config.interval == 2
            app.resume()
            root.after(1000, finish)

        def finish():
            assert not app.monitor.paused.is_set()
            checks.append("resume")
            app.close()

        root.after(15000, exercise)
        root.after(25000, lambda: failed(TimeoutError, "GUI check timed out", None))
        root.mainloop()
        assert not app.monitor.thread.is_alive()
        assert not errors, errors
        assert len(checks) == 10
        print("GUI passed: " + ", ".join(checks) + ", clean shutdown")


if __name__ == "__main__":
    main()
