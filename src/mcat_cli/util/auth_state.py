from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from .json_file import read_json_object, write_json_object_locked


def read_auth_state_file(path: str) -> dict[str, Any]:
    return read_json_object(
        path,
        not_found_message=f"auth state file not found: {path}",
        invalid_json_prefix="invalid auth state file JSON",
        expected_object_message="invalid auth state file: expected object",
    )


def write_auth_state_file(path: str, state_doc: dict[str, Any]) -> None:
    write_json_object_locked(
        path,
        state_doc,
        busy_message=f"auth state file is busy: {path}",
    )


def default_auth_state_file() -> str:
    fd, path = tempfile.mkstemp(prefix="mcat-auth-", suffix=".json")
    os.close(fd)
    Path(path).unlink(missing_ok=True)
    return path
