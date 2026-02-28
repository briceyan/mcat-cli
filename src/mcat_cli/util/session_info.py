from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import json5
from dataclasses_json import Undefined, dataclass_json

from .atomic_files import write_json_object_locked
from .common import as_optional_str


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass(frozen=True, slots=True)
class SessionInfo:
    version: int | None = None
    endpoint: str | None = None
    key_ref: str | None = None
    session_id: str | None = None
    session_mode: str | None = None
    protocol_version: str | None = None
    server_capabilities: dict[str, Any] | None = None

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> SessionInfo:
        session_info = cls.from_dict(doc)
        session_info.validate()
        return session_info

    def to_doc(self) -> dict[str, Any]:
        return self.to_dict()

    def validate(self) -> None:
        if not isinstance(self.version, int):
            raise ValueError("invalid session info file: missing version")
        if not as_optional_str(self.endpoint):
            raise ValueError("invalid session info file: missing endpoint")
        if not as_optional_str(self.key_ref):
            raise ValueError("invalid session info file: missing key_ref")
        if self.server_capabilities is not None and not isinstance(
            self.server_capabilities, dict
        ):
            raise ValueError(
                "invalid session info file: server_capabilities must be an object"
            )


def read_session_info_model(path: str) -> SessionInfo:
    return SessionInfo.from_doc(_read_session_info_doc(path))


def write_session_info_model(path: str, session_info: SessionInfo) -> None:
    session_info.validate()
    write_json_object_locked(
        path,
        session_info.to_doc(),
        busy_message=f"session info file is busy: {path}",
    )


def read_session_info(path: str) -> dict[str, Any]:
    return read_session_info_model(path).to_doc()


def write_session_info(path: str, session_info: dict[str, Any]) -> None:
    write_session_info_model(path, SessionInfo.from_doc(session_info))


def _read_session_info_doc(path: str) -> dict[str, Any]:
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"session info file not found: {path}") from None
    except OSError as exc:
        raise ValueError(f"unable to read session info file: {exc}") from None

    try:
        doc = json5.loads(raw)
    except Exception as exc:
        raise ValueError(f"invalid session info JSON/JSON5: {exc}") from None

    if not isinstance(doc, dict):
        raise ValueError("invalid session info file: expected JSON object")
    return doc
