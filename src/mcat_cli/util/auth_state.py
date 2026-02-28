from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import json5
from dataclasses_json import Undefined, dataclass_json

from .atomic_files import write_json_object_locked
from .common import as_optional_str


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass(frozen=True, slots=True)
class AuthState:
    version: int | None = None
    endpoint: str | None = None
    flow: str | None = None
    state: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> AuthState:
        auth_state = cls.from_dict(doc)
        auth_state.validate()
        return auth_state

    def to_doc(self) -> dict[str, Any]:
        return self.to_dict()

    def validate(self) -> None:
        if not isinstance(self.version, int):
            raise ValueError("invalid auth state file: missing version")
        if not as_optional_str(self.endpoint):
            raise ValueError("invalid auth state file: missing endpoint")
        if not as_optional_str(self.flow):
            raise ValueError("invalid auth state file: missing flow")
        if not isinstance(self.state, dict):
            raise ValueError("invalid auth state file: missing state object")


def read_auth_state(path: str) -> AuthState:
    return AuthState.from_doc(_read_auth_state_doc(path))


def write_auth_state(path: str, auth_state: AuthState) -> None:
    auth_state.validate()
    write_json_object_locked(
        path,
        auth_state.to_doc(),
        busy_message=f"auth state file is busy: {path}",
    )


def read_auth_state_file(path: str) -> dict[str, Any]:
    return read_auth_state(path).to_doc()


def write_auth_state_file(path: str, state_doc: dict[str, Any]) -> None:
    write_auth_state(path, AuthState.from_doc(state_doc))


def default_auth_state_file() -> str:
    fd, path = tempfile.mkstemp(prefix="mcat-auth-", suffix=".json")
    os.close(fd)
    Path(path).unlink(missing_ok=True)
    return path


def _read_auth_state_doc(path: str) -> dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"auth state file not found: {path}") from None

    try:
        doc = json5.loads(raw)
    except Exception as exc:
        raise ValueError(f"invalid auth state file JSON/JSON5: {exc}") from None

    if not isinstance(doc, dict):
        raise ValueError("invalid auth state file: expected object")
    return doc
