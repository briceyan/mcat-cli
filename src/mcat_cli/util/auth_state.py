from __future__ import annotations

from typing import Any

from .auth_info import (
    default_auth_info_file,
    read_auth_info_doc,
    write_auth_info_doc,
)


def read_auth_state_file(path: str) -> dict[str, Any]:
    return read_auth_info_doc(path)


def write_auth_state_file(path: str, state_doc: dict[str, Any]) -> None:
    write_auth_info_doc(path, state_doc)


def default_auth_state_file() -> str:
    return default_auth_info_file()
