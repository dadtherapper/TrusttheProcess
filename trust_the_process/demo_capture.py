"""Render and capture this application's own Tk windows without desktop interaction.

Windows only; PrintWindow captures our window's GDI rendering, including while the desktop
is locked. Uses only Python's standard library and the app's normal runtime dependencies.
No desktop capture, foreground activation, keyboard, or mouse injection is performed.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import struct
import tempfile
import tkinter as tk
import zlib
from ctypes import wintypes
from pathlib import Path

from .config import Config
from .gui import Application


def capture_window(root: tk.Tk | tk.Toplevel, path: Path) -> None:
    if os.name != "nt":
        raise RuntimeError("This renderer uses Windows PrintWindow.")
    root.update_idletasks()
    user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    user32.GetWindowDC.argtypes = [wintypes.HWND]
    user32.GetWindowDC.restype = wintypes.HDC
    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
    gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteDC.argtypes = [wintypes.HDC]
    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
    gdi32.GetDIBits.argtypes = [
        wintypes.HDC,
        wintypes.HBITMAP,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.UINT,
    ]
    handle = user32.GetAncestor(root.winfo_id(), 2)
    rect = wintypes.RECT()
    user32.GetWindowRect(handle, ctypes.byref(rect))
    width, height = rect.right - rect.left, rect.bottom - rect.top
    source = user32.GetWindowDC(handle)
    target = gdi32.CreateCompatibleDC(source)
    bitmap = gdi32.CreateCompatibleBitmap(source, width, height)
    original = gdi32.SelectObject(target, bitmap)
    try:
        if not user32.PrintWindow(handle, target, 2):
            raise RuntimeError("PrintWindow could not render the application window.")
        # A top-down 32-bit DIB avoids row inversion and platform image dependencies.
        header = struct.pack(
            "<IiiHHIIiiII", 40, width, -height, 1, 32, 0, width * height * 4, 0, 0, 0, 0
        )
        info = ctypes.create_string_buffer(header)
        pixels = ctypes.create_string_buffer(width * height * 4)
        gdi32.SelectObject(target, original)
        if gdi32.GetDIBits(target, bitmap, 0, height, pixels, info, 0) != height:
            raise RuntimeError("Application pixels could not be read.")
        raw = pixels.raw
        if len(set(raw[::131])) < 8:
            raise RuntimeError("Capture appears blank; refusing to save a misleading screenshot.")
        rows = bytearray()
        for y in range(height):
            rows.append(0)
            row = raw[y * width * 4 : (y + 1) * width * 4]
            rgb = bytearray(width * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = row[2::4], row[1::4], row[0::4]
            rows.extend(rgb)

        def chunk(kind: bytes, data: bytes) -> bytes:
            return (
                struct.pack(">I", len(data))
                + kind
                + data
                + struct.pack(">I", zlib.crc32(kind + data))
            )

        path.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 6))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi32.SelectObject(target, original)
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(target)
        user32.ReleaseDC(handle, source)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/screenshots"))
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    errors = []
    with tempfile.TemporaryDirectory(prefix="ttp-render-") as temporary:
        root = tk.Tk()
        app = Application(root, Config(interval=1, min_samples=5), Path(temporary), demo=True)

        def failed(kind, value, traceback):
            errors.append(f"{kind.__name__}: {value}")
            app.close()

        root.report_callback_exception = failed
        pages = iter(app.NAV)

        def next_page():
            name = next(pages, None)
            if name is None:
                root.geometry("1100x720")
                app.navigate("Processes")
                root.after(400, minimum)
                return
            app.navigate(name)
            if name == "Processes":
                p = next(p for p in app.state.snapshot.processes if p.pid == 620)
                app.process_table.tree.selection_set(p.key)
                app.select_process()
            elif name == "Connections":
                c = next(c for c in app.state.snapshot.connections if c.pid == 620)
                app.connection_table.tree.selection_set(c.key)
                app.select_connection()
            elif name == "Findings":
                f = next(f for f in app.state.findings if f["rule_id"] == "NET-FIRST")
                app.finding_table.tree.selection_set(f["id"])
                app.select_finding()
            root.after(400, lambda: save(name))

        def save(name):
            capture_window(root, args.output / (name.lower() + ".png"))
            root.after(100, next_page)

        def minimum():
            capture_window(root, args.output / "processes-minimum.png")
            app.close()

        root.after(15000, next_page)
        root.after(30000, lambda: failed(TimeoutError, "render timed out", None))
        root.mainloop()
        assert not errors, errors
    print(json.dumps({"output": str(args.output.resolve()), "screenshots": 7, "simulated": True}))


if __name__ == "__main__":
    main()
