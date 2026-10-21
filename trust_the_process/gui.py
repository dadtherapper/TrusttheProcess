"""Tk desktop investigation console. Only this module touches widgets, on the main thread."""

from __future__ import annotations

import json
import queue
import time
import tkinter as tk
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .config import Config
from .engine import Monitor, ViewState
from .models import Process, clean, severity_for

BG = "#0c111b"
PANEL = "#131d2b"
SIDEBAR = "#0f1723"
TEXT = "#e5edf8"
MUTED = "#92a5be"
ACCENT = "#51d4ba"
LINE = "#243247"
COLORS = {"High": "#ff7a90", "Medium": "#f4c16d", "Low": "#79c7f6", "Informational": MUTED}
FINDINGS_PAGE_SIZE = 200


def number(value: float | None, suffix: str = "", digits: int = 1) -> str:
    return "—" if value is None else f"{value:,.{digits}f}{suffix}"


def time_label(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%H:%M:%S")
    except ValueError:
        return clean(value)


def dated_label(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%m-%d %H:%M:%S")
    except ValueError:
        return clean(value)


class Table(ttk.Frame):
    def __init__(self, parent, columns: list[tuple[str, str, int]], on_select=None) -> None:
        super().__init__(parent)
        self.columns = columns
        self.rows: dict[str, tuple] = {}
        self.sort_column = 0
        self.descending = False
        self.on_sort = None
        self.tree = ttk.Treeview(
            self, columns=[c[0] for c in columns], show="headings", selectmode="browse"
        )
        for index, (key, title, width) in enumerate(columns):
            self.tree.heading(key, text=title, command=lambda i=index: self.sort(i))
            self.tree.column(
                key, width=width, minwidth=65, stretch=True, anchor="w" if index == 0 else "center"
            )
        vertical = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        for severity, color in COLORS.items():
            self.tree.tag_configure(severity, foreground=color)
        if on_select:
            self.tree.bind("<<TreeviewSelect>>", lambda _: on_select())

    def selected(self) -> str | None:
        selected = self.tree.selection()
        return selected[0] if selected else None

    def update_rows(self, rows: list[tuple[str, tuple, str]]) -> None:
        current = set(self.tree.get_children())
        wanted = {r[0] for r in rows}
        for old in current - wanted:
            self.tree.delete(old)
        self.rows = {}
        for key, values, tag in rows:
            self.rows[key] = values
            safe = tuple(clean(v, 1000) for v in values)
            if key in current:
                if self.tree.item(key, "values") != safe or self.tree.item(key, "tags") != (tag,):
                    self.tree.item(key, values=safe, tags=(tag,))
            else:
                self.tree.insert("", "end", iid=key, values=safe, tags=(tag,))
                current.add(key)
        self.order()

    def sort(self, index: int) -> None:
        self.descending = not self.descending if index == self.sort_column else False
        self.sort_column = index
        if self.on_sort:
            self.on_sort()
        else:
            self.order()

    def order(self) -> None:
        def key(row):
            value = self.rows[row][self.sort_column]
            if self.columns[self.sort_column][0] == "severity":
                return (0, {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}.get(value, -1))
            if isinstance(value, (int, float)):
                return (0, value)
            return (1, str(value).casefold())

        ordered = (
            list(self.rows) if self.on_sort else sorted(self.rows, key=key, reverse=self.descending)
        )
        for index, row in enumerate(ordered):
            self.tree.move(row, "", index)


class Chart(tk.Canvas):
    def __init__(self, parent, title: str, color: str = ACCENT, height: int = 150) -> None:
        super().__init__(parent, background=PANEL, highlightthickness=0, height=height)
        self.title, self.color = title, color
        self.values: list[float | None] = []
        self.bind("<Configure>", lambda _: self.draw())

    def set_values(self, values: list[float | None]) -> None:
        self.values = values[-100:]
        self.draw()

    def draw(self) -> None:
        self.delete("all")
        w, h = max(self.winfo_width(), 160), max(self.winfo_height(), 100)
        self.create_text(18, 18, anchor="w", text=self.title, fill=MUTED, font=("Segoe UI", 10))
        values = [v for v in self.values if v is not None]
        if not values:
            self.create_text(w / 2, h / 2, text="Waiting for observations", fill=MUTED)
            return
        maximum = max(1.0, max(values) * 1.15)
        for fraction in (0, 0.5, 1):
            y = h - 26 - fraction * (h - 65)
            self.create_line(18, y, w - 18, y, fill=LINE)
        points = []
        for i, value in enumerate(self.values):
            if value is None:
                if len(points) >= 4:
                    self.create_line(*points, fill=self.color, width=2)
                points = []
                continue
            x = 18 + i / max(1, len(self.values) - 1) * (w - 36)
            y = h - 26 - value / maximum * (h - 65)
            points.extend((x, y))
        if len(points) >= 4:
            self.create_line(*points, fill=self.color, width=2)
        elif points:
            x, y = points
            self.create_oval(x - 3, y - 3, x + 3, y + 3, fill=self.color, outline="")
        self.create_text(
            w - 18,
            18,
            anchor="e",
            text=number(self.values[-1]),
            fill=self.color,
            font=("Segoe UI", 11, "bold"),
        )
        self.create_text(18, h - 10, anchor="w", text="older", fill=MUTED, font=("Segoe UI", 8))
        self.create_text(
            w - 18, h - 10, anchor="e", text="latest", fill=MUTED, font=("Segoe UI", 8)
        )


class Application:
    NAV = ("Dashboard", "Processes", "Connections", "Findings", "History", "Settings")
    DESCRIPTIONS = {
        "Dashboard": "Local evidence. Explainable findings. A clearer view of your endpoint.",
        "Processes": "Inspect executable identity, relationships, resources, and observed behavior.",
        "Connections": "Observed TCP / UDP sockets • no packet capture or per-process byte counts.",
        "Findings": "Context to investigate • evidence scores are not malware probabilities.",
        "History": "Persisted observations and finding timelines • collected while monitoring runs.",
        "Settings": "Local learning, collection preferences, and explicit indicator-sharing controls.",
    }

    def __init__(self, root: tk.Tk, config: Config, folder: Path, demo: bool = False) -> None:
        self.root, self.config, self.folder, self.demo = root, config, folder, demo
        self.state: ViewState | None = None
        self.active = "Dashboard"
        self.closing = False
        self.notice_until = 0.0
        self.monitor = Monitor(config, folder, demo)
        self.status = tk.StringVar(value="Starting local monitoring…")
        self.snapshot_time = tk.StringVar(value="Waiting for first observation")
        self.search = tk.StringVar()
        self.process_filter = tk.StringVar(value="All processes")
        self.connection_search = tk.StringVar()
        self.connection_filter = tk.StringVar(value="All addresses")
        self.severity_filter = tk.StringVar(value="All severities")
        self.unack_only = tk.BooleanVar(value=False)
        self.finding_page = 0
        self.redaction = tk.BooleanVar(value=True)
        self.provider = tk.StringVar(value="VirusTotal")
        self.indicator = tk.StringVar()
        self._style()
        self._build()
        self.search.trace_add("write", lambda *_: self.render_processes())
        self.connection_search.trace_add("write", lambda *_: self.render_connections())
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.report_callback_exception = self.callback_error
        self.monitor.start()
        root.after(100, self.poll)

    def _style(self) -> None:
        self.root.title(
            "Trust the Process • " + ("SIMULATED DEMO" if self.demo else "Endpoint Console")
        )
        self.root.geometry("1440x900")
        self.root.minsize(1100, 720)
        self.root.configure(background=BG)
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            ".",
            font=("Segoe UI", 10),
            background=BG,
            foreground=TEXT,
            bordercolor=LINE,
            lightcolor=LINE,
            darkcolor=LINE,
            troughcolor=PANEL,
            fieldbackground=PANEL,
            selectbackground="#23483f",
            selectforeground=TEXT,
        )
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Panel.TLabel", background=PANEL)
        style.configure("Title.TLabel", font=("Segoe UI", 25, "bold"))
        style.configure("TButton", padding=(12, 8), background="#1c2c3e", borderwidth=0)
        style.map(
            "TButton",
            background=[("active", "#2a4058"), ("disabled", PANEL)],
            foreground=[("disabled", "#65778d")],
        )
        style.configure("Accent.TButton", background=ACCENT, foreground="#09241e")
        style.map("Accent.TButton", background=[("active", "#83e8d4")])
        style.map(
            "Accent.TButton",
            background=[("disabled", "#18343a"), ("active", "#83e8d4")],
            foreground=[("disabled", ACCENT)],
        )
        style.configure(
            "TScrollbar", background=LINE, arrowcolor=MUTED, troughcolor=PANEL, bordercolor=PANEL
        )
        style.map("TScrollbar", background=[("active", "#344559")])
        style.configure("TEntry", padding=8, insertcolor=TEXT)
        style.configure("TCombobox", padding=6, arrowcolor=ACCENT)
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", PANEL)],
            selectbackground=[("readonly", PANEL)],
            selectforeground=[("readonly", TEXT)],
        )
        style.configure(
            "Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=TEXT,
            rowheight=31,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#1b293b",
            foreground=MUTED,
            padding=(8, 10),
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map(
            "Treeview", background=[("selected", "#254a52")], foreground=[("selected", "#ffffff")]
        )
        style.configure("TCheckbutton", background=BG, padding=4)
        style.map("TCheckbutton", background=[("active", BG)])
        self.root.option_add("*TCombobox*Listbox.background", PANEL)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)

    def label(self, parent, text: str, **kwargs):
        return ttk.Label(parent, text=text, **kwargs)

    def _build(self) -> None:
        sidebar = tk.Frame(self.root, bg=SIDEBAR, width=205)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(
            sidebar, text="T / P", bg=SIDEBAR, fg=ACCENT, font=("Segoe UI", 28, "bold"), anchor="w"
        ).pack(fill="x", padx=24, pady=(26, 0))
        tk.Label(
            sidebar,
            text="TRUST THE PROCESS",
            bg=SIDEBAR,
            fg=TEXT,
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).pack(fill="x", padx=24, pady=(8, 3))
        tk.Label(
            sidebar,
            text="Verify the Behavior.",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x", padx=24, pady=(0, 35))
        self.nav_buttons = {}
        for i, name in enumerate(self.NAV):
            button = tk.Button(
                sidebar,
                text=f"0{i + 1}    {name}",
                anchor="w",
                bd=0,
                bg=SIDEBAR,
                fg=MUTED,
                activebackground="#1c3241",
                activeforeground=ACCENT,
                padx=22,
                pady=15,
                font=("Segoe UI", 11),
                cursor="hand2",
                command=lambda n=name: self.navigate(n),
            )
            button.pack(fill="x", padx=8, pady=2)
            self.nav_buttons[name] = button
        tk.Label(
            sidebar,
            text="READ-ONLY MONITORING\nv0.1.0  /  LOCAL FIRST",
            justify="left",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 8),
            anchor="w",
        ).pack(side="bottom", fill="x", padx=24, pady=25)
        body = ttk.Frame(self.root, padding=(25, 20, 25, 10))
        body.pack(side="left", fill="both", expand=True)
        if self.demo:
            tk.Label(
                body,
                text="SIMULATED DEMO  •  Synthetic processes, connections, and reputation. "
                "No host collection or external lookups.",
                bg="#3a2d19",
                fg="#f4c16d",
                anchor="w",
                padx=12,
                pady=9,
                font=("Segoe UI", 9, "bold"),
            ).pack(fill="x", pady=(0, 15))
        top = ttk.Frame(body)
        top.pack(fill="x")
        self.title = self.label(top, "Dashboard", style="Title.TLabel")
        self.title.pack(side="left")
        self.resume_button = ttk.Button(top, text="Resume", command=self.resume)
        self.resume_button.pack(side="right", padx=(6, 0))
        self.pause_button = ttk.Button(top, text="Pause", command=self.pause)
        self.pause_button.pack(side="right", padx=(6, 0))
        self.start_button = ttk.Button(
            top, text="Start Monitoring", command=self.resume, style="Accent.TButton"
        )
        self.start_button.pack(side="right", padx=(12, 0))
        self.description = self.label(body, self.DESCRIPTIONS["Dashboard"], style="Muted.TLabel")
        self.description.pack(anchor="w", pady=(7, 18))
        self.pages = {name: ttk.Frame(body) for name in self.NAV}
        self._dashboard(self.pages["Dashboard"])
        self._processes(self.pages["Processes"])
        self._connections(self.pages["Connections"])
        self._findings(self.pages["Findings"])
        self._history(self.pages["History"])
        self._settings(self.pages["Settings"])
        footer = ttk.Frame(body)
        footer.pack(side="bottom", fill="x", pady=(12, 0))
        ttk.Label(footer, textvariable=self.status, style="Muted.TLabel", wraplength=720).pack(
            side="left", anchor="w"
        )
        ttk.Label(footer, textvariable=self.snapshot_time, style="Muted.TLabel").pack(side="right")
        self.navigate("Dashboard")

    def _dashboard(self, page) -> None:
        cards = ttk.Frame(page)
        cards.pack(fill="x", pady=(0, 16))
        self.metrics = {}
        for i, (name, label) in enumerate(
            (
                ("processes", "OBSERVED PROCESSES"),
                ("connections", "ACTIVE SOCKETS"),
                ("findings", "UNACKNOWLEDGED FINDINGS"),
                ("learning", "ESTABLISHED BASELINES"),
            )
        ):
            cards.columnconfigure(i, weight=1, uniform="cards")
            card = tk.Frame(cards, background=PANEL, padx=17, pady=15)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            tk.Label(card, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(
                anchor="w"
            )
            value = tk.Label(card, text="—", bg=PANEL, fg=ACCENT, font=("Segoe UI", 27, "bold"))
            value.pack(anchor="w", pady=(7, 0))
            self.metrics[name] = value
        self.source_label = self.label(
            page,
            "TELEMETRY  /  Waiting for first observation",
            style="Muted.TLabel",
            wraplength=1000,
        )
        self.source_label.pack(anchor="w", pady=(0, 15))
        chart_row = ttk.Frame(page)
        chart_row.pack(fill="both", expand=True, pady=(0, 16))
        self.cpu_chart = Chart(chart_row, "SYSTEM CPU  /  percent")
        self.cpu_chart.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.net_chart = Chart(chart_row, "OBSERVED SOCKETS  /  snapshot count", "#79c7f6")
        self.net_chart.pack(side="left", fill="both", expand=True)
        heading = ttk.Frame(page)
        heading.pack(fill="x", pady=(0, 9))
        self.label(heading, "Investigation queue", font=("Segoe UI", 14, "bold")).pack(side="left")
        self.severity_counts = self.label(heading, "", style="Muted.TLabel")
        self.severity_counts.pack(side="right")
        self.recent = Table(
            page,
            [
                ("severity", "Severity", 80),
                ("process", "Process", 150),
                ("finding", "Finding", 300),
                ("time", "Last observed", 100),
            ],
            self.open_recent,
        )
        self.recent.pack(fill="both", expand=True)
        self.recent.tree.configure(height=7)
        self.recent.descending = True
        self.label(
            page,
            "A finding is a reason to investigate. High resource use, an unknown file, "
            "or a missing metric alone does not establish compromise.",
            style="Muted.TLabel",
            wraplength=1000,
        ).pack(anchor="w", pady=(12, 0))

    def _toolbar(self, page) -> ttk.Frame:
        bar = ttk.Frame(page)
        bar.pack(fill="x", pady=(0, 12))
        return bar

    def _text(self, parent, height: int = 10) -> tk.Text:
        frame = ttk.Frame(parent)
        text = tk.Text(
            frame,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            padx=17,
            pady=15,
            font=("Segoe UI", 10),
            height=height,
            highlightthickness=0,
            selectbackground="#285361",
            state="disabled",
        )
        scroll = ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)
        frame.pack(fill="both", expand=True)
        return text

    @staticmethod
    def set_text(widget: tk.Text, value: str) -> None:
        value = clean(value, 250000)
        old_position = widget.yview()[0]
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")
        widget.yview_moveto(old_position)

    def _split(self, page):
        pane = tk.PanedWindow(
            page,
            orient="horizontal",
            background=BG,
            bd=0,
            sashwidth=10,
            sashrelief="flat",
            opaqueresize=True,
        )
        pane.pack(fill="both", expand=True)
        left, right = ttk.Frame(pane), ttk.Frame(pane)
        pane.add(left, minsize=440, stretch="always", width=720)
        pane.add(right, minsize=285, stretch="always", width=355)
        return left, right

    def _processes(self, page) -> None:
        bar = self._toolbar(page)
        ttk.Entry(bar, textvariable=self.search, width=30).pack(side="left")
        combo = ttk.Combobox(
            bar,
            textvariable=self.process_filter,
            state="readonly",
            width=24,
            values=("All processes", "With findings", "With active sockets"),
        )
        combo.pack(side="left", padx=10)
        combo.bind("<<ComboboxSelected>>", lambda _: self.render_processes())
        self.process_count = self.label(
            bar, "Search name, PID, path, or command", style="Muted.TLabel"
        )
        self.process_count.pack(side="left")
        left, right = self._split(page)
        self.process_table = Table(
            left,
            [
                ("name", "Process", 165),
                ("pid", "PID", 65),
                ("cpu", "CPU %", 75),
                ("rss", "RSS MiB", 85),
                ("net", "Sockets", 70),
                ("risk", "Score", 65),
                ("baseline", "Baseline", 100),
            ],
            self.select_process,
        )
        self.process_table.sort_column, self.process_table.descending = 5, True
        self.process_table.pack(fill="both", expand=True)
        actions = ttk.Frame(right)
        actions.pack(fill="x", pady=(0, 9))
        ttk.Button(actions, text="Timeline", command=self.process_history).pack(side="left")
        ttk.Button(
            actions, text="Export report", command=lambda: self.export("investigation")
        ).pack(side="left", padx=6)
        ttk.Button(
            right, text="View process relationships", command=self.process_relationships
        ).pack(anchor="w", pady=(0, 9))
        self.process_detail = self._text(right)
        self.set_text(
            self.process_detail,
            "Select a process to inspect its identity and behavior.\n\n"
            "CPU is psutil's per-process percentage; it can exceed 100% across cores.\n"
            "RSS is resident memory. A dash means unavailable.\n\n"
            "Score combines findings for the process lifetime, including historical findings.",
        )

    def _connections(self, page) -> None:
        bar = self._toolbar(page)
        ttk.Entry(bar, textvariable=self.connection_search, width=32).pack(side="left")
        combo = ttk.Combobox(
            bar,
            textvariable=self.connection_filter,
            state="readonly",
            width=20,
            values=("All addresses", "Public destinations", "New sockets"),
        )
        combo.pack(side="left", padx=10)
        combo.bind("<<ComboboxSelected>>", lambda _: self.render_connections())
        self.label(bar, "Search endpoints, process, or PID", style="Muted.TLabel").pack(side="left")
        left, right = self._split(page)
        self.connection_table = Table(
            left,
            [
                ("process", "Process / PID", 155),
                ("proto", "Protocol", 80),
                ("local", "Local endpoint", 180),
                ("remote", "Remote endpoint", 180),
                ("state", "State", 105),
                ("class", "Address", 80),
            ],
            self.select_connection,
        )
        self.connection_table.pack(fill="both", expand=True)
        self.connection_detail = self._text(right)
        self.set_text(
            self.connection_detail,
            "Select a socket observation.\n\n"
            "First and last seen refer to this observed episode, not the actual socket creation time. "
            "A new socket means a tuple absent from the preceding successful snapshot.\n\n"
            "Missing PID ownership remains unattributed. Short-lived traffic may be missed.",
        )
        self._lookup_controls(page)

    def _lookup_controls(self, page) -> None:
        frame = ttk.Frame(page)
        frame.pack(fill="x", pady=(12, 0))
        self.label(frame, "Manual reputation", style="Muted.TLabel").pack(side="left", padx=(0, 10))
        ttk.Combobox(
            frame,
            textvariable=self.provider,
            state="readonly",
            width=13,
            values=("VirusTotal", "AbuseIPDB"),
        ).pack(side="left")
        ttk.Entry(frame, textvariable=self.indicator, width=35).pack(side="left", padx=8)
        ttk.Button(frame, text="Look up selected indicator", command=self.lookup).pack(side="left")
        self.label(
            page,
            "Select a remote address, or paste a public IP / SHA-256. Enable a provider "
            "in Settings first. Only this indicator is shared when you click Look up.",
            style="Muted.TLabel",
            wraplength=1050,
        ).pack(anchor="w", pady=(6, 0))

    def _findings(self, page) -> None:
        bar = self._toolbar(page)
        combo = ttk.Combobox(
            bar,
            textvariable=self.severity_filter,
            state="readonly",
            width=18,
            values=("All severities", "High", "Medium", "Low", "Informational"),
        )
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda _: self.filter_findings())
        ttk.Checkbutton(
            bar, text="Unacknowledged only", variable=self.unack_only, command=self.filter_findings
        ).pack(side="left", padx=10)
        ttk.Button(bar, text="Export JSON", command=lambda: self.export("json")).pack(side="right")
        ttk.Button(bar, text="Export CSV", command=lambda: self.export("csv")).pack(
            side="right", padx=8
        )
        left, right = self._split(page)
        self.finding_table = Table(
            left,
            [
                ("severity", "Severity", 85),
                ("process", "Process", 145),
                ("title", "Finding", 250),
                ("time", "Last observed", 95),
                ("ack", "Reviewed", 75),
            ],
            self.select_finding,
        )
        self.finding_table.pack(fill="both", expand=True)
        self.finding_table.descending = True
        self.finding_table.on_sort = self.filter_findings
        actions = ttk.Frame(right)
        actions.pack(fill="x", pady=(0, 9))
        ttk.Button(actions, text="Acknowledge", command=self.acknowledge).pack(side="left")
        ttk.Button(actions, text="Process timeline", command=self.finding_history).pack(
            side="left", padx=6
        )
        self.finding_detail = self._text(right)
        self.set_text(
            self.finding_detail,
            "Select a finding to see its evidence, expectations, "
            "source, limitations, and recommended investigation steps.\n\n"
            "Acknowledgment records review; it does not remove the evidence score.",
        )
        paging = ttk.Frame(page)
        paging.pack(side="bottom", fill="x", pady=(8, 0))
        self.previous_findings = ttk.Button(
            paging, text="Previous", command=lambda: self.change_finding_page(-1)
        )
        self.previous_findings.pack(side="left")
        self.next_findings = ttk.Button(
            paging, text="Next", command=lambda: self.change_finding_page(1)
        )
        self.next_findings.pack(side="left", padx=8)
        self.finding_page_label = self.label(paging, "", style="Muted.TLabel")
        self.finding_page_label.pack(side="left")

    def _history(self, page) -> None:
        self.label(
            page,
            "System trend • retained snapshots are written about every 15 seconds "
            "in live mode, on pause, and at shutdown.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 12))
        self.history_chart = Chart(page, "SYSTEM MEMORY  /  percent", "#b1a0f0", height=160)
        self.history_chart.pack(fill="x", pady=(0, 12))
        self.history_table = Table(
            page,
            [
                ("time", "Observed (local time)", 155),
                ("processes", "Processes", 85),
                ("connections", "Sockets", 85),
                ("cpu", "CPU %", 80),
                ("memory", "Memory %", 85),
                ("source", "Source", 290),
            ],
        )
        self.history_table.pack(fill="both", expand=True)
        self.history_table.tree.configure(height=4)
        self.label(
            page,
            "Historical process lifetimes • select to inspect retained samples",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(12, 7))
        self.execution_table = Table(
            page,
            [
                ("name", "Process", 155),
                ("pid", "PID", 70),
                ("path", "Executable", 450),
                ("last", "Last observed", 100),
            ],
            self.select_execution,
        )
        self.execution_table.tree.configure(height=5)
        self.execution_table.pack(fill="both", expand=True)
        self.label(
            page,
            "Open a process Timeline from Processes or Findings for persisted resource "
            "samples, connection episodes, and the finding timeline. History starts when "
            "this application observes activity.",
            style="Muted.TLabel",
            wraplength=1000,
        ).pack(anchor="w", pady=(12, 0))

    def _settings(self, page) -> None:
        # A scrollable settings form stays usable at Windows display scaling factors.
        canvas = tk.Canvas(page, bg=BG, highlightthickness=0)
        scroll = ttk.Scrollbar(page, command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        form = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=form, anchor="nw")
        form.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        self.settings_vars = {}
        self.label(form, "Collection & local learning", font=("Segoe UI", 15, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 12)
        )
        labels = [
            ("interval", "Sampling interval (seconds)"),
            ("retention_days", "Retention (days)"),
            ("min_samples", "Minimum baseline samples"),
            ("sustained_samples", "Consecutive resource anomalies"),
            ("memory_ratio", "Memory baseline multiplier"),
            ("memory_delta_mb", "Minimum memory increase (MiB)"),
            ("cpu_delta", "CPU increase above p95 (percentage points)"),
            ("connection_burst", "New socket / destination threshold"),
            ("baseline_window", "Rolling baseline window (samples)"),
        ]
        for row, (key, label) in enumerate(labels, 1):
            self.label(form, label, style="Muted.TLabel").grid(
                row=row, column=0, sticky="w", pady=5
            )
            variable = tk.StringVar(value=str(getattr(self.config, key)))
            self.settings_vars[key] = variable
            ttk.Entry(form, textvariable=variable, width=15).grid(
                row=row, column=1, sticky="w", padx=25
            )
        row = len(labels) + 1
        self.label(
            form,
            "Optional reputation • manual, indicator-only sharing",
            font=("Segoe UI", 14, "bold"),
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(24, 8))
        self.label(
            form,
            "Enabling a provider permits manual lookups of public IPs or executable SHA-256. "
            "The provider receives the indicator and your source IP. VirusTotal may add queried indicators "
            "to its dataset. No files, command lines, usernames, or private addresses are sent. "
            "Review provider terms; VirusTotal Public API has non-commercial restrictions. "
            "Keys are read from environment variables; never paste them here.",
            style="Muted.TLabel",
            wraplength=790,
        ).grid(row=row + 1, column=0, columnspan=2, sticky="w", pady=(0, 9))
        self.abuse_enabled = tk.BooleanVar(value=self.config.abuseipdb_enabled and not self.demo)
        self.vt_enabled = tk.BooleanVar(value=self.config.virustotal_enabled and not self.demo)
        for offset, text, variable in (
            (2, "Enable AbuseIPDB • TTP_ABUSEIPDB_API_KEY", self.abuse_enabled),
            (3, "Enable VirusTotal • TTP_VIRUSTOTAL_API_KEY", self.vt_enabled),
        ):
            check = ttk.Checkbutton(form, text=text, variable=variable)
            check.grid(row=row + offset, column=0, columnspan=2, sticky="w", pady=3)
            if self.demo:
                check.state(["disabled"])
        actions = ttk.Frame(form)
        actions.grid(row=row + 4, column=0, columnspan=2, sticky="w", pady=16)
        ttk.Button(
            actions, text="Save settings", style="Accent.TButton", command=self.save_settings
        ).pack(side="left")
        ttk.Button(actions, text="Inspect baselines", command=self.inspect_baselines).pack(
            side="left", padx=10
        )
        ttk.Button(actions, text="Reset learned baselines", command=self.reset_baselines).pack(
            side="left"
        )
        ttk.Checkbutton(
            form,
            text="Redact exported reports (removes identifying free text, addresses, "
            "paths, usernames, hashes, and PIDs)",
            variable=self.redaction,
        ).grid(row=row + 5, column=0, columnspan=2, sticky="w", pady=8)
        self.label(
            form,
            "Telemetry capabilities\npsutil: process resources, ancestry, executable metadata, "
            "TCP/UDP socket snapshots, best-effort PID attribution. No packets, DNS events, kernel events, "
            "or per-process byte counters. Optional Sysmon ingestion is not part of v0.1.\n\n"
            f"Local data directory: {self.folder}\nRetention also uses hard row caps to bound disk usage. "
            "The database contains sensitive local history. Protect it with your Windows account permissions.",
            style="Muted.TLabel",
            wraplength=800,
        ).grid(row=row + 6, column=0, columnspan=2, sticky="w", pady=(12, 20))
        form.columnconfigure(0, weight=0, minsize=440)
        form.columnconfigure(1, weight=1)

    def navigate(self, name: str) -> None:
        self.pages[self.active].pack_forget()
        self.active = name
        self.pages[name].pack(fill="both", expand=True)
        self.title.configure(text=name)
        self.description.configure(text=self.DESCRIPTIONS[name])
        for nav, button in self.nav_buttons.items():
            button.configure(
                bg="#1b343d" if nav == name else SIDEBAR, fg=ACCENT if nav == name else MUTED
            )
        self.render()

    def render(self) -> None:
        if not self.state:
            return
        {
            "Dashboard": self.render_dashboard,
            "Processes": self.render_processes,
            "Connections": self.render_connections,
            "Findings": self.render_findings,
            "History": self.render_history,
            "Settings": lambda: None,
        }[self.active]()

    def render_dashboard(self) -> None:
        if not self.state:
            return
        state, snapshot = self.state, self.state.snapshot
        unack = [f for f in state.findings if not f["acknowledged"]]
        values = {
            "processes": len(snapshot.processes),
            "connections": len(snapshot.connections) if snapshot.network_available else "—",
            "findings": len(unack),
            "learning": sum(b["ready"] for b in state.baselines.values()),
        }
        for name, value in values.items():
            self.metrics[name].configure(text=value)
        self.source_label.configure(
            text=f"TELEMETRY  /  {snapshot.source}  •  "
            f"System memory {number(snapshot.system_memory, '%')}  •  "
            + (
                "No packets / no process bytes"
                if snapshot.network_available
                else "NETWORK UNAVAILABLE"
            )
        )
        self.cpu_chart.set_values([r.get("cpu") for r in state.history])
        self.net_chart.set_values(
            [
                r.get("connections") if r.get("network_available", True) else None
                for r in state.history
            ]
        )
        counts = Counter(f["severity"] for f in unack)
        self.severity_counts.configure(
            text="    ".join(f"{s} {counts[s]}" for s in ("High", "Medium", "Low"))
        )
        self.recent.update_rows(
            [
                (
                    f["id"],
                    (f["severity"], f["process_name"], f["title"], time_label(f["last_seen"])),
                    f["severity"],
                )
                for f in unack[:30]
            ]
        )

    def render_processes(self) -> None:
        if not self.state:
            return
        query, mode = self.search.get().casefold(), self.process_filter.get()
        rows = []
        for p in self.state.snapshot.processes:
            score = self.state.risks.get(p.key, 0)
            if query not in f"{p.name} {p.pid} {p.exe} {p.command}".casefold():
                continue
            if mode == "With findings" and not self.state.process_findings.get(p.key):
                continue
            if mode == "With active sockets" and not p.connections:
                continue
            baseline = self.state.baselines[p.key]
            rows.append(
                (
                    p.key,
                    (
                        p.name,
                        p.pid,
                        round(p.cpu, 1) if p.cpu is not None else "—",
                        round(p.rss / 1024**2, 1) if p.rss is not None else "—",
                        p.connections if p.connections is not None else "—",
                        score,
                        "Established" if baseline["ready"] else f"Learning {baseline['samples']}",
                    ),
                    severity_for(score),
                )
            )
        self.process_table.update_rows(rows)
        self.process_count.configure(text=f"{len(rows)} processes • search / sort by column")
        self.select_process()

    def selected_process(self) -> Process | None:
        key = self.process_table.selected()
        return (
            next((p for p in self.state.snapshot.processes if p.key == key), None)
            if self.state
            else None
        )

    def select_process(self) -> None:
        p = self.selected_process()
        if not p:
            self.set_text(
                self.process_detail,
                "Select a current process to inspect.\n\n"
                "If a process exited or was filtered out, its retained samples are "
                "available in History. A dash means unavailable; the evidence score "
                "summarizes findings for a process lifetime.",
            )
            return
        b = self.state.baselines[p.key]
        now = datetime.fromisoformat(self.state.snapshot.timestamp).timestamp()
        duration = (
            number(max(0, now - p.started), " sec", 0) if p.started is not None else "Unavailable"
        )
        start = (
            datetime.fromtimestamp(p.started, UTC).astimezone().isoformat(timespec="seconds")
            if p.started
            else "Unavailable"
        )
        by_key = {proc.key: proc for proc in self.state.snapshot.processes}
        ancestors, seen, cursor = [], {p.key}, p
        while cursor.parent_key and cursor.parent_key not in seen and len(ancestors) < 12:
            seen.add(cursor.parent_key)
            parent = by_key.get(cursor.parent_key)
            if not parent:
                break
            ancestors.append(f"{parent.name} ({parent.pid}) • {parent.exe or 'path unavailable'}")
            cursor = parent
        children = [
            f"{child.name} ({child.pid})" for child in by_key.values() if child.parent_key == p.key
        ]
        findings = self.state.process_findings.get(p.key, [])
        details = [
            f"{p.name}  /  PID {p.pid}",
            f"Lifetime identity: {p.key}",
            f"Evidence score: {self.state.risks[p.key]}/100 ({severity_for(self.state.risks[p.key])})",
            "Score includes findings recorded for this process lifetime.",
            "",
            "IDENTITY",
            f"Path: {p.exe or 'Unavailable'}",
            f"SHA-256: {p.sha256 or 'Pending / unreadable / size-limited'}",
            f"User: {p.username or 'Unavailable'}",
            f"Command: {p.command or 'Unavailable'}",
            f"Status: {p.status or 'Unavailable'}",
            f"Started: {start}",
            f"Duration: {duration}",
            "",
            "RELATIONSHIPS (observed ancestry)",
            f"Parent PID: {p.ppid}",
            *(ancestors or ["No verified parent lifetime available"]),
            "Children: " + (", ".join(children) or "None observed"),
            "",
            "CURRENT RESOURCES",
            f"CPU: {number(p.cpu, '%')}",
            f"RSS: {number(p.rss / 1024**2 if p.rss is not None else None, ' MiB')}",
            f"Memory share: {number(p.memory_percent, '%')}",
            "",
            "BEHAVIORAL BASELINE",
            f"{'Established' if b['ready'] else 'Learning / Insufficient Baseline'} • {b['samples']} polls",
            f"RSS median: {number(b['rss']['median'] / 1024**2 if b['rss']['median'] is not None else None, ' MiB')} ({b['rss']['count']} samples)",
            f"CPU median: {number(b['cpu']['median'], '%')} ({b['cpu']['count']} samples)",
            f"Socket median: {number(b['connections']['median'])} ({b['connections']['count']} samples)",
            "Baseline is keyed by full executable path and file metadata, pooling instances per poll.",
            "",
            "NETWORK OBSERVATIONS",
            "Distinct remote destinations (all address classes): "
            + str(
                len(
                    {
                        c.remote_ip
                        for c in self.state.snapshot.connections
                        if c.process_key == p.key and c.remote_ip is not None
                    }
                )
            ),
            f"Active sockets: {p.connections if p.connections is not None else 'Unavailable'}",
            f"New remote sockets: {p.new_connections if p.new_connections is not None else 'Unavailable'}",
            f"Public destinations ({len(p.destinations)}): "
            + (", ".join(p.destinations) or "None observed"),
            "Remote ports: " + (", ".join(map(str, p.ports)) or "None observed"),
            "",
            "RECORDED FINDINGS",
            *(
                [
                    f"[{f['severity']}] {f['title']} • {f['occurrences']} observations"
                    for f in findings
                ]
                or ["None recorded"]
            ),
            "",
            "LIMITATIONS",
            "Unavailable fields: " + (", ".join(p.limitations) or "None reported"),
            "No signature verification or packet visibility. Missing telemetry is not evidence of compromise.",
        ]
        self.set_text(self.process_detail, "\n".join(details))

    def render_connections(self) -> None:
        if not self.state:
            return
        query, mode = self.connection_search.get().casefold(), self.connection_filter.get()
        rows = []
        for c in self.state.snapshot.connections:
            if query not in f"{c.process_name} {c.pid} {c.local_ip} {c.remote_ip}".casefold():
                continue
            if mode == "Public destinations" and c.address_class != "public":
                continue
            if mode == "New sockets" and not c.new:
                continue
            rows.append(
                (
                    c.key,
                    (
                        f"{c.process_name or 'Unattributed'} / {c.pid if c.pid is not None else '—'}",
                        c.protocol,
                        f"{c.local_ip}:{c.local_port}",
                        f"{c.remote_ip}:{c.remote_port}" if c.remote_ip else "—",
                        c.status,
                        c.address_class,
                    ),
                    "Low" if c.new else "Informational",
                )
            )
        self.connection_table.update_rows(rows)
        self.select_connection(update_indicator=False)

    def select_connection(self, update_indicator: bool = True) -> None:
        if not self.state:
            return
        key = self.connection_table.selected()
        c = next((c for c in self.state.snapshot.connections if c.key == key), None)
        if c:
            if update_indicator:
                self.indicator.set(c.remote_ip or "")
            self.set_text(
                self.connection_detail,
                "SOCKET OBSERVATION\n\n"
                + "\n".join(
                    f"{field.replace('_', ' ').title()}: {value if value is not None else 'Unavailable'}"
                    for field, value in asdict(c).items()
                )
                + "\n\nLIMITATIONS\n"
                "PID attribution is a best-effort lifetime check around a socket snapshot. "
                "It is not authoritative kernel attribution. No packets, DNS, or byte volume is measured.",
            )
        else:
            self.set_text(
                self.connection_detail,
                "Select a current socket observation.\n\n"
                "Socket details are cleared when the selected episode is no longer visible. "
                "Retained episodes remain in the associated process timeline. "
                "Snapshots contain no packet or byte-volume measurements.",
            )

    def render_findings(self) -> None:
        if not self.state:
            return
        mode = self.severity_filter.get()
        filtered = [
            f
            for f in self.state.findings
            if (mode == "All severities" or f["severity"] == mode)
            and (not self.unack_only.get() or not f["acknowledged"])
        ]
        fields = ("severity", "process_name", "title", "last_seen", "acknowledged")
        column = fields[self.finding_table.sort_column]

        def sort_key(f):
            value = f[column]
            if column == "severity":
                return {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}.get(value, -1)
            return value if isinstance(value, bool) else str(value).casefold()

        filtered.sort(key=sort_key, reverse=self.finding_table.descending)
        page_size = FINDINGS_PAGE_SIZE
        self.finding_page = max(0, min(self.finding_page, (len(filtered) - 1) // page_size))
        start = self.finding_page * page_size
        rows = [
            (
                f["id"],
                (
                    f["severity"],
                    f["process_name"],
                    f["title"],
                    time_label(f["last_seen"]),
                    "Yes" if f["acknowledged"] else "No",
                ),
                f["severity"],
            )
            for f in filtered[start : start + page_size]
        ]
        self.finding_table.update_rows(rows)
        self.select_finding()
        self.finding_page_label.configure(
            text=f"{start + 1 if filtered else 0}–{min(start + page_size, len(filtered))} of {len(filtered)} findings"
        )
        self.previous_findings.state(["!disabled"] if self.finding_page else ["disabled"])
        self.next_findings.state(
            ["!disabled"] if start + page_size < len(filtered) else ["disabled"]
        )

    def filter_findings(self) -> None:
        self.finding_page = 0
        self.render_findings()

    def change_finding_page(self, delta: int) -> None:
        self.finding_page += delta
        self.render_findings()

    def selected_finding(self) -> dict | None:
        key = self.finding_table.selected()
        return (
            next((f for f in self.state.findings if f["id"] == key), None) if self.state else None
        )

    def select_finding(self) -> None:
        f = self.selected_finding()
        if not f:
            self.set_text(
                self.finding_detail, "Select a finding to inspect its evidence and context."
            )
        if f:
            text = (
                f"{'SIMULATED  /  ' if f['simulated'] else ''}{f['title']}\n"
                f"{f['rule_id']} • {f['severity']} • evidence weight {f['weight']}\n\n"
                f"Process: {f['process_name']} ({f['process_key']})\n"
                f"First observed: {f['timestamp']}\nLast observed: {f['last_seen']}\n"
                f"Occurrences: {f['occurrences']}\nAcknowledged: {f['acknowledged']}\n\n"
                f"OBSERVED\n{f['observed']}\n\nEXPECTED\n{f['expected'] or 'No established expectation'}\n\n"
                f"EXPLANATION\n{f['explanation']}\n\nEVIDENCE\n{json.dumps(f['evidence'], indent=2)}\n\n"
                f"INVESTIGATION\n{f['recommendation']}\n\nSOURCE\n{f['source']}\n"
                f"Confidence: {f['confidence']}\nLimitations: {f['limitations']}"
            )
            self.set_text(self.finding_detail, text)

    def render_history(self) -> None:
        if self.state:
            self.history_chart.set_values([r.get("memory") for r in self.state.history])
            self.history_table.update_rows(
                [
                    (
                        r["timestamp"],
                        (
                            dated_label(r["timestamp"]),
                            r["processes"],
                            r["connections"] if r.get("network_available", True) else "—",
                            number(r.get("cpu")),
                            number(r.get("memory")),
                            r["source"],
                        ),
                        "Informational",
                    )
                    for r in self.state.history
                ]
            )
            self.execution_table.update_rows(
                [
                    (
                        r["process_key"],
                        (
                            r["name"],
                            r["pid"],
                            r.get("exe") or "Unavailable",
                            dated_label(r["timestamp"]),
                        ),
                        "Informational",
                    )
                    for r in self.state.executions
                ]
            )

    def select_execution(self) -> None:
        key = self.execution_table.selected()
        if key:
            self.monitor.submit("history", process_key=key)

    def open_recent(self) -> None:
        key = self.recent.selected()
        if key:
            self.navigate("Findings")
            self.severity_filter.set("All severities")
            self.unack_only.set(False)
            # A recent item can sit anywhere in the user's chosen global sort order.
            self.finding_table.sort_column = 3
            self.finding_table.descending = True
            ordered = sorted(self.state.findings, key=lambda f: f["last_seen"], reverse=True)
            position = next((i for i, f in enumerate(ordered) if f["id"] == key), 0)
            self.finding_page = position // FINDINGS_PAGE_SIZE
            self.render_findings()
            if self.finding_table.tree.exists(key):
                self.finding_table.tree.selection_set(key)
                self.finding_table.tree.see(key)

    def pause(self) -> None:
        self.monitor.submit("pause")

    def resume(self) -> None:
        self.monitor.submit("resume")

    def acknowledge(self) -> None:
        finding = self.selected_finding()
        if finding:
            self.monitor.submit("acknowledge", finding_id=finding["id"])

    def process_history(self) -> None:
        p = self.selected_process()
        if p:
            self.monitor.submit("history", process_key=p.key)

    def finding_history(self) -> None:
        f = self.selected_finding()
        if f:
            self.monitor.submit("history", process_key=f["process_key"])

    def process_relationships(self) -> None:
        selected = self.selected_process()
        if selected is None:
            return
        by_key = {p.key: p for p in self.state.snapshot.processes}
        ancestors = []
        cursor, seen = selected, {selected.key}
        while cursor.parent_key in by_key and cursor.parent_key not in seen and len(ancestors) < 6:
            cursor = by_key[cursor.parent_key]
            seen.add(cursor.key)
            ancestors.insert(0, cursor)
        children = [p for p in by_key.values() if p.parent_key == selected.key]
        window = tk.Toplevel(self.root)
        window.title("Observed process relationships")
        window.geometry("860x600")
        window.configure(bg=BG)
        self.label(
            window, "Observed ancestry → selected process → children", font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=20, pady=15)
        self.label(
            window,
            "Verified creation times only • up to six ancestors and eight children. "
            "This is a snapshot, not a complete event-derived process tree.",
            style="Muted.TLabel",
            wraplength=800,
        ).pack(anchor="w", padx=20)
        canvas = tk.Canvas(window, bg=PANEL, highlightthickness=0)
        canvas.pack(fill="both", expand=True, padx=20, pady=20)

        def draw(_=None):
            canvas.delete("all")
            width, height = max(600, canvas.winfo_width()), max(350, canvas.winfo_height())
            center = (width * 0.5, height * 0.5)
            groups = [
                (ancestors, width * 0.16, MUTED),
                ([selected], center[0], ACCENT),
                (children[:8], width * 0.84, "#79c7f6"),
            ]
            positions = {}
            for group, x, _color in groups:
                for i, process in enumerate(group):
                    positions[process.key] = (x, (i + 1) * height / (len(group) + 1))
            for process in [*ancestors, selected, *children[:8]]:
                if process.parent_key in positions:
                    x1, y1 = positions[process.parent_key]
                    x2, y2 = positions[process.key]
                    canvas.create_line(x1, y1, x2, y2, fill=LINE, width=2, arrow="last")
            for group, _x, color in groups:
                for process in group:
                    x, y = positions[process.key]
                    canvas.create_rectangle(x - 95, y - 20, x + 95, y + 20, fill=BG, outline=color)
                    canvas.create_text(
                        x,
                        y,
                        text=clean(f"{process.name[:23]}\nPID {process.pid}"),
                        fill=color,
                        font=("Segoe UI", 9),
                    )
            if not ancestors:
                canvas.create_text(
                    width * 0.16, height * 0.5, text="Parent unavailable", fill=MUTED
                )
            if not children:
                canvas.create_text(
                    width * 0.84, height * 0.5, text="No observed children", fill=MUTED
                )

        canvas.bind("<Configure>", draw)

    def show_text_window(self, title: str, text: str) -> None:
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("900x650")
        window.configure(bg=BG)
        self.set_text(self._text(window), text)

    def show_history(self, data: dict) -> None:
        observations = data["observations"]
        text = f"PROCESS TIMELINE  /  {data['process_key']}\n\nPERSISTED RESOURCE SAMPLES\n"
        text += (
            "\n".join(
                f"{r['timestamp']} • {r['name']} • CPU {number(r.get('cpu'), '%')} • "
                f"RSS {number(r['rss'] / 1024**2 if r.get('rss') is not None else None, ' MiB')} • "
                f"Sockets {r.get('connections')}"
                for r in observations
            )
            or "No persisted samples yet"
        )
        text += "\n\nFINDING TIMELINE\n" + "\n".join(
            f"{f['timestamp']} → {f['last_seen']}  [{f['severity']}] {f['title']}\n{f['observed']}"
            for f in reversed(data["findings"])
        )
        text += "\n\nCONNECTION EPISODES\n" + "\n".join(
            f"{c['first_seen']} → {c['last_seen']}  {c['protocol']}  "
            f"{c['local_ip']}:{c['local_port']} → {c['remote_ip']}:{c['remote_port']} [{c['status']}]"
            for c in data["connections"]
        )
        text += "\n\nLATEST PERSISTED IDENTITY\n" + json.dumps(
            observations[-1] if observations else {}, indent=2
        )
        window = tk.Toplevel(self.root)
        window.title("Process investigation timeline")
        window.geometry("900x650")
        window.configure(bg=BG)
        ttk.Button(
            window,
            text="Export this investigation",
            command=lambda: self.export("investigation", process_key=data["process_key"]),
        ).pack(anchor="w", padx=15, pady=10)
        self.set_text(self._text(window), text)

    def inspect_baselines(self) -> None:
        if self.state:
            self.show_text_window("Learned baselines", json.dumps(self.state.baselines, indent=2))

    def reset_baselines(self) -> None:
        if messagebox.askyesno(
            "Reset learned baselines",
            "Delete learned baselines and restart learning? "
            "Observation and finding history will be retained.",
            parent=self.root,
        ):
            self.monitor.submit("reset")

    def save_settings(self) -> None:
        try:
            data = asdict(self.config)
            for key, variable in self.settings_vars.items():
                data[key] = (
                    float(variable.get())
                    if key in {"interval", "memory_ratio", "memory_delta_mb", "cpu_delta"}
                    else int(variable.get())
                )
            data["abuseipdb_enabled"], data["virustotal_enabled"] = (
                self.abuse_enabled.get(),
                self.vt_enabled.get(),
            )
            candidate = Config(**data)
            candidate.validate()
            self.monitor.submit("settings", config=data)
        except ValueError as error:
            messagebox.showerror("Check settings", str(error), parent=self.root)

    def export(self, mode: str, process_key: str | None = None) -> None:
        if not self.state:
            return
        process = self.selected_process() if mode == "investigation" else None
        process_key = process_key or (process.key if process else None)
        if mode == "investigation" and not process_key:
            self.status.set("Select a process before exporting its investigation.")
            return
        extension = ".csv" if mode == "csv" else ".json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            defaultextension=extension,
            filetypes=[("CSV findings" if mode == "csv" else "JSON report", "*" + extension)],
            initialfile=("SIMULATED-" if self.demo else "") + "trust-the-process" + extension,
        )
        if path:
            self.monitor.submit(
                "export",
                path=Path(path),
                mode=mode,
                redacted=self.redaction.get(),
                process_key=process_key,
            )

    def lookup(self) -> None:
        indicator = self.indicator.get().strip()
        process_key = None
        if self.state:
            c = next(
                (
                    c
                    for c in self.state.snapshot.connections
                    if c.key == self.connection_table.selected()
                ),
                None,
            )
            # Do not associate pasted, unrelated indicators with the selected process.
            if c and c.remote_ip == indicator:
                process_key = c.process_key
            p = self.selected_process()
            if len(indicator) == 64 and p and p.sha256 and p.sha256.lower() == indicator.lower():
                process_key = p.key
        self.monitor.submit(
            "lookup",
            provider=self.provider.get(),
            indicator=indicator,
            kind="sha256" if len(indicator) == 64 else "ip",
            process_key=process_key,
        )

    def poll(self) -> None:
        if self.closing:
            return
        # Schedule before rendering so one bad callback cannot permanently stop UI polling.
        self.root.after(150, self.poll)
        try:
            self.state = self.monitor.states.get_nowait()
            self.snapshot_time.set("Observed " + time_label(self.state.snapshot.timestamp))
            if time.monotonic() >= self.notice_until:
                self.status.set(
                    "Paused • showing last observation"
                    if self.monitor.paused.is_set()
                    else "Monitoring • " + ("SIMULATED" if self.demo else "local host")
                )
                if self.state.snapshot.limitations and not self.demo:
                    self.status.set(" • ".join(self.state.snapshot.limitations))
            self.render()
        except queue.Empty:
            pass
        for _ in range(16):
            try:
                kind, payload = self.monitor.messages.get_nowait()
            except queue.Empty:
                break
            if kind == "history":
                self.show_history(payload)
            elif kind == "reputation":
                self.show_text_window(
                    "Reputation • provider context", json.dumps(payload, indent=2)
                )
            elif kind == "settings":
                self.config = Config(**payload)
            else:
                self.status.set(clean(payload, 500))
                self.notice_until = time.monotonic() + 8
        self.pause_button.state(["disabled"] if self.monitor.paused.is_set() else ["!disabled"])
        self.resume_button.state(["!disabled"] if self.monitor.paused.is_set() else ["disabled"])
        self.start_button.state(
            ["disabled"] if self.state and not self.monitor.paused.is_set() else ["!disabled"]
        )
        if not self.monitor.thread.is_alive():
            self.status.set("Monitoring stopped. Restart the application to try again.")
            for button in (self.pause_button, self.resume_button, self.start_button):
                button.state(["disabled"])

    def callback_error(self, kind, value, traceback) -> None:
        import logging

        logging.error("GUI callback failed: %s", kind.__name__)
        self.status.set(f"Interface action failed ({kind.__name__}). Monitoring continues.")
        self.notice_until = time.monotonic() + 8

    def close(self) -> None:
        if not self.closing:
            self.closing = True
            self.status.set("Closing • waiting for collection and pending I/O…")
            self.monitor.shutdown()
            self.root.after(100, self._finish_close)

    def _finish_close(self) -> None:
        if self.monitor.thread.is_alive():
            self.root.after(100, self._finish_close)
        else:
            self.root.destroy()
