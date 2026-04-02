from __future__ import annotations

from pathlib import Path
from typing import Any

import json5

from .atomic_files import write_json_object_locked
from .common import as_optional_str

CURRENT_CONNECTION_VERSION = 2


def read_connection_file(path: str) -> dict[str, Any]:
    doc = _read_connection_doc(path)
    return _normalize_connection_doc(doc)


def write_connection_file(path: str, doc: dict[str, Any]) -> None:
    normalized = _normalize_connection_doc(doc)
    write_json_object_locked(
        path,
        normalized,
        busy_message=f"connection file is busy: {path}",
    )


def _read_connection_doc(path: str) -> dict[str, Any]:
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"connection file not found: {path}") from None
    except OSError as exc:
        raise ValueError(f"unable to read connection file: {exc}") from None

    try:
        doc = json5.loads(raw)
    except Exception as exc:
        raise ValueError(f"invalid connection file JSON/JSON5: {exc}") from None

    if not isinstance(doc, dict):
        raise ValueError("invalid connection file: expected JSON object")
    return doc


def _normalize_connection_doc(doc: dict[str, Any]) -> dict[str, Any]:
    # Backward-compatibility for legacy auth state files.
    if as_optional_str(doc.get("endpoint")) and isinstance(doc.get("state"), dict):
        kind = as_optional_str(doc.get("kind"))
        flow = as_optional_str(doc.get("flow"))
        if kind is None and flow is not None:
            state = dict(doc["state"])
            normalized = {
                "version": CURRENT_CONNECTION_VERSION,
                "kind": "http",
                "endpoint": doc["endpoint"],
                "key_ref": as_optional_str(doc.get("key_ref"))
                or as_optional_str(state.get("input_key_ref")),
                "flow": flow,
                "state": state,
            }
            bridge = doc.get("bridge")
            if not isinstance(bridge, dict):
                bridge = doc.get("proxy")
            if isinstance(bridge, dict):
                normalized["bridge"] = bridge
            return _validate_connection_doc(normalized)

    return _validate_connection_doc(dict(doc))


def _validate_connection_doc(doc: dict[str, Any]) -> dict[str, Any]:
    version = doc.get("version")
    if not isinstance(version, int):
        raise ValueError("invalid connection file: missing version")

    kind = as_optional_str(doc.get("kind"))
    if kind not in {"http", "stdio"}:
        raise ValueError("invalid connection file: missing kind")

    endpoint = as_optional_str(doc.get("endpoint"))
    if not endpoint:
        raise ValueError("invalid connection file: missing endpoint")

    state = doc.get("state")
    if not isinstance(state, dict):
        raise ValueError("invalid connection file: missing state object")

    key_ref = doc.get("key_ref")
    if key_ref is not None and as_optional_str(key_ref) is None:
        raise ValueError("invalid connection file: key_ref must be a string")

    flow = doc.get("flow")
    if flow is not None and as_optional_str(flow) is None:
        raise ValueError("invalid connection file: flow must be a string")

    bridge = doc.get("bridge")
    if bridge is None:
        bridge = doc.get("proxy")
    if bridge is not None and not isinstance(bridge, dict):
        raise ValueError("invalid connection file: bridge must be an object")

    normalized = {
        "version": version,
        "kind": kind,
        "endpoint": endpoint,
        "key_ref": as_optional_str(key_ref),
        "flow": as_optional_str(flow),
        "state": dict(state),
    }
    if isinstance(bridge, dict):
        normalized["bridge"] = dict(bridge)
    return normalized
