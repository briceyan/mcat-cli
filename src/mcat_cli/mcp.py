from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any
from urllib import parse as urlparse

from .util.files import locked_file, write_text_atomic

LOGGER = logging.getLogger("mcat.mcp")


def init_session(*, endpoint: str, key_ref: str, sess_info_file: str) -> dict[str, Any]:
    LOGGER.info("mcp.init requested endpoint=%s", endpoint)
    normalized_endpoint = _normalize_url(endpoint, field="ENDPOINT")
    normalized_key_ref = _normalize_key_ref(key_ref)
    if not sess_info_file.strip():
        raise ValueError("SESS_INFO_FILE is required")

    session_doc = {
        "version": 1,
        "session_id": str(uuid.uuid4()),
        "key_ref": normalized_key_ref,
        "endpoint": normalized_endpoint,
    }
    serialized = json.dumps(session_doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n"

    lock_path = f"{sess_info_file}.lock"
    try:
        with locked_file(lock_path):
            write_text_atomic(sess_info_file, serialized)
    except BlockingIOError:
        raise ValueError(f"session info file is busy: {sess_info_file}") from None

    return {
        "session_id": session_doc["session_id"],
        "session_file": str(Path(sess_info_file)),
    }


def list_tools(*, sess_info_file: str) -> dict[str, Any]:
    LOGGER.info("mcp.tool.list requested sess_info_file=%s", sess_info_file)
    raise NotImplementedError("tool listing is not implemented yet")


def call_tool(
    *, tool_name: str, args_input: str, sess_info_file: str
) -> dict[str, Any]:
    LOGGER.info("mcp.tool.call requested tool_name=%s", tool_name)
    _ = (args_input, sess_info_file)
    raise NotImplementedError("tool call is not implemented yet")


def _normalize_url(value: str, *, field: str) -> str:
    text = value.strip()
    parsed = urlparse.urlsplit(text)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute URL")
    return text


def _normalize_key_ref(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("KEY_REF is required")

    if value.startswith("env://"):
        name = value[len("env://") :].strip()
        if not name:
            raise ValueError("invalid KEY_REF: missing env var name")
        return f"env://{name}"

    if value.startswith(".env://"):
        rest = value[len(".env://") :]
        if ":" not in rest:
            raise ValueError("invalid KEY_REF: expected .env://path:VAR")
        path, name = rest.rsplit(":", 1)
        if not path.strip() or not name.strip():
            raise ValueError("invalid KEY_REF: expected .env://path:VAR")
        return f".env://{path.strip()}:{name.strip()}"

    if value.startswith("json://"):
        path = value[len("json://") :].strip()
        if not path:
            raise ValueError("invalid KEY_REF: missing json path")
        return f"json://{path}"

    if "://" not in value:
        # Convenience shorthand: bare path means json://path.
        return f"json://{value}"

    raise ValueError("invalid KEY_REF scheme (expected env://, .env://, or json://)")
