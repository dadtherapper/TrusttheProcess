"""Atomic local writes that do not clobber predictable temporary filenames."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO


@contextmanager
def atomic_text(
    path: Path, encoding: str = "utf-8", newline: str | None = None
) -> Iterator[TextIO]:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            newline=newline,
            dir=path.parent,
            prefix=".ttp-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            yield stream
        temporary.replace(path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)
