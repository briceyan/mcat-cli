from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .atomic_files import write_text_atomic


class JsonValueFileNotFoundError(ValueError):
    pass


def read_json_value(
    path: str,
    *,
    not_found_message: str,
    invalid_json_prefix: str,
) -> Any:
    file_path = Path(path)
    if not file_path.exists():
        raise JsonValueFileNotFoundError(not_found_message)
    try:
        raw = file_path.read_text(encoding="utf-8")
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{invalid_json_prefix}: {exc.msg}") from None


def write_json_value(
    path: str,
    payload: Any,
    *,
    overwrite: bool,
    exists_message: str,
) -> None:
    file_path = Path(path)
    if file_path.exists() and not overwrite:
        raise ValueError(exists_message)
    serialized = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    write_text_atomic(path, serialized)
