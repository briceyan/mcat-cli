from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .atomic_files import locked_file, write_text_atomic


def read_json_object(
    path: str,
    *,
    not_found_message: str,
    invalid_json_prefix: str,
    expected_object_message: str,
    read_error_prefix: str | None = None,
) -> dict[str, Any]:
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(not_found_message) from None
    except OSError as exc:
        if read_error_prefix is not None:
            raise ValueError(f"{read_error_prefix}: {exc}") from None
        raise

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{invalid_json_prefix}: {exc.msg}") from None

    if not isinstance(parsed, dict):
        raise ValueError(expected_object_message)
    return parsed


def write_json_object_locked(
    path: str,
    payload: dict[str, Any],
    *,
    busy_message: str,
) -> None:
    serialized = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    lock_path = f"{path}.lock"
    try:
        with locked_file(lock_path):
            write_text_atomic(path, serialized)
    except BlockingIOError:
        raise ValueError(busy_message) from None
