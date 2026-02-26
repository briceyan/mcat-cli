from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO


def write_text_atomic(path: str | Path, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            file_obj.write(content)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


@contextmanager
def locked_file(path: str | Path, mode: str = "a+") -> Iterator[TextIO]:
    import fcntl

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open(mode, encoding="utf-8") as file_obj:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield file_obj
        finally:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
