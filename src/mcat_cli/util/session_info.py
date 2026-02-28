from __future__ import annotations

from typing import Any

from .json_file import read_json_object, write_json_object_locked


def read_session_info(path: str) -> dict[str, Any]:
    return read_json_object(
        path,
        not_found_message=f"session info file not found: {path}",
        invalid_json_prefix="invalid session info JSON",
        expected_object_message="invalid session info file: expected JSON object",
        read_error_prefix="unable to read session info file",
    )


def write_session_info(path: str, session_info: dict[str, Any]) -> None:
    write_json_object_locked(
        path,
        session_info,
        busy_message=f"session info file is busy: {path}",
    )
