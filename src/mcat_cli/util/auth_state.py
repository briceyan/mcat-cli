from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .atomic_files import locked_file, write_text_atomic


def read_auth_state_file(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"auth state file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid auth state file JSON: {exc.msg}") from None
    if not isinstance(data, dict):
        raise ValueError("invalid auth state file: expected object")
    return data


def write_auth_state_file(path: str, state_doc: dict[str, Any]) -> None:
    lock_path = f"{path}.lock"
    content = json.dumps(state_doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        with locked_file(lock_path):
            write_text_atomic(path, content)
    except BlockingIOError:
        raise ValueError(f"auth state file is busy: {path}") from None


def default_auth_state_file() -> str:
    fd, path = tempfile.mkstemp(prefix="mcat-auth-", suffix=".json")
    os.close(fd)
    Path(path).unlink(missing_ok=True)
    return path
