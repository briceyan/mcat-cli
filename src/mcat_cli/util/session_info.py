from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .atomic_files import locked_file, write_text_atomic


def read_session_info(path: str) -> dict[str, Any]:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"session info file not found: {path}") from None
    except OSError as exc:
        raise ValueError(f"unable to read session info file: {exc}") from None

    try:
        info = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid session info JSON: {exc.msg}") from None

    if not isinstance(info, dict):
        raise ValueError("invalid session info file: expected JSON object")
    return info


def write_session_info(path: str, session_info: dict[str, Any]) -> None:
    serialized = (
        json.dumps(
            session_info,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n"
    )
    lock_path = f"{path}.lock"
    try:
        with locked_file(lock_path):
            write_text_atomic(path, serialized)
    except BlockingIOError:
        raise ValueError(f"session info file is busy: {path}") from None
