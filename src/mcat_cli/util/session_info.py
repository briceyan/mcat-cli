from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .common import as_optional_str
from .json_file import read_json_object, write_json_object_locked


@dataclass(frozen=True, slots=True)
class SessionInfo:
    version: int
    endpoint: str
    key_ref: str
    session_id: str | None = None
    session_mode: str | None = None
    protocol_version: str | None = None
    server_capabilities: dict[str, Any] | None = None
    extras: dict[str, Any] = field(default_factory=dict)


def session_info_from_doc(doc: dict[str, Any]) -> SessionInfo:
    version = doc.get("version")
    if not isinstance(version, int):
        raise ValueError("invalid session info file: missing version")

    endpoint = as_optional_str(doc.get("endpoint"))
    if not endpoint:
        raise ValueError("invalid session info file: missing endpoint")

    key_ref = as_optional_str(doc.get("key_ref"))
    if not key_ref:
        raise ValueError("invalid session info file: missing key_ref")

    session_id = as_optional_str(doc.get("session_id"))
    session_mode = as_optional_str(doc.get("session_mode"))
    protocol_version = as_optional_str(doc.get("protocol_version"))

    raw_capabilities = doc.get("server_capabilities")
    server_capabilities: dict[str, Any] | None = None
    if isinstance(raw_capabilities, dict):
        server_capabilities = dict(raw_capabilities)
    elif raw_capabilities is not None:
        raise ValueError("invalid session info file: server_capabilities must be an object")

    known_keys = {
        "version",
        "endpoint",
        "key_ref",
        "session_id",
        "session_mode",
        "protocol_version",
        "server_capabilities",
    }
    extras = {key: value for key, value in doc.items() if key not in known_keys}

    return SessionInfo(
        version=version,
        endpoint=endpoint,
        key_ref=key_ref,
        session_id=session_id,
        session_mode=session_mode,
        protocol_version=protocol_version,
        server_capabilities=server_capabilities,
        extras=extras,
    )


def session_info_to_doc(session_info: SessionInfo) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "version": session_info.version,
        "endpoint": session_info.endpoint,
        "key_ref": session_info.key_ref,
    }
    if session_info.session_id is not None:
        doc["session_id"] = session_info.session_id
    if session_info.session_mode is not None:
        doc["session_mode"] = session_info.session_mode
    if session_info.protocol_version is not None:
        doc["protocol_version"] = session_info.protocol_version
    if session_info.server_capabilities is not None:
        doc["server_capabilities"] = dict(session_info.server_capabilities)
    if session_info.extras:
        doc.update(session_info.extras)
    return doc


def read_session_info(path: str) -> dict[str, Any]:
    return read_session_info_doc(path)


def read_session_info_doc(path: str) -> dict[str, Any]:
    doc = read_json_object(
        path,
        not_found_message=f"session info file not found: {path}",
        invalid_json_prefix="invalid session info JSON",
        expected_object_message="invalid session info file: expected JSON object",
        read_error_prefix="unable to read session info file",
    )
    return session_info_to_doc(session_info_from_doc(doc))


def read_session_info_model(path: str) -> SessionInfo:
    return session_info_from_doc(read_session_info_doc(path))


def write_session_info(path: str, session_info: dict[str, Any]) -> None:
    write_session_info_doc(path, session_info)


def write_session_info_doc(path: str, doc: dict[str, Any]) -> None:
    normalized = session_info_to_doc(session_info_from_doc(doc))
    write_json_object_locked(
        path,
        normalized,
        busy_message=f"session info file is busy: {path}",
    )


def write_session_info_model(path: str, session_info: SessionInfo) -> None:
    write_session_info_doc(path, session_info_to_doc(session_info))
