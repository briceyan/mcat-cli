from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import as_optional_str
from .json_file import read_json_object, write_json_object_locked


@dataclass(frozen=True, slots=True)
class AuthInfo:
    version: int
    endpoint: str
    flow: str
    state: dict[str, Any]


def auth_info_from_doc(doc: dict[str, Any]) -> AuthInfo:
    version = doc.get("version")
    if not isinstance(version, int):
        raise ValueError("invalid auth state file: missing version")

    endpoint = as_optional_str(doc.get("endpoint"))
    if not endpoint:
        raise ValueError("invalid auth state file: missing endpoint")

    flow = as_optional_str(doc.get("flow"))
    if not flow:
        raise ValueError("invalid auth state file: missing flow")

    state = doc.get("state")
    if not isinstance(state, dict):
        raise ValueError("invalid auth state file: missing state object")

    return AuthInfo(
        version=version,
        endpoint=endpoint,
        flow=flow,
        state=dict(state),
    )


def auth_info_to_doc(auth_info: AuthInfo) -> dict[str, Any]:
    return {
        "version": auth_info.version,
        "endpoint": auth_info.endpoint,
        "flow": auth_info.flow,
        "state": dict(auth_info.state),
    }


def read_auth_info(path: str) -> AuthInfo:
    return auth_info_from_doc(read_auth_info_doc(path))


def read_auth_info_doc(path: str) -> dict[str, Any]:
    doc = read_json_object(
        path,
        not_found_message=f"auth state file not found: {path}",
        invalid_json_prefix="invalid auth state file JSON",
        expected_object_message="invalid auth state file: expected object",
    )
    return auth_info_to_doc(auth_info_from_doc(doc))


def write_auth_info(path: str, auth_info: AuthInfo) -> None:
    write_auth_info_doc(path, auth_info_to_doc(auth_info))


def write_auth_info_doc(path: str, doc: dict[str, Any]) -> None:
    write_json_object_locked(
        path,
        auth_info_to_doc(auth_info_from_doc(doc)),
        busy_message=f"auth state file is busy: {path}",
    )


def default_auth_info_file() -> str:
    fd, path = tempfile.mkstemp(prefix="mcat-auth-", suffix=".json")
    os.close(fd)
    Path(path).unlink(missing_ok=True)
    return path
