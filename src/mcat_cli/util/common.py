from __future__ import annotations

from typing import Any, Literal
from urllib import parse as urlparse

import json5


def as_optional_str(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def normalize_url(value: str, *, field: str) -> str:
    text = value.strip()
    parsed = urlparse.urlsplit(text)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute URL")
    return text


def normalize_mcp_endpoint(
    value: str, *, field: str
) -> tuple[Literal["http", "unix"], str]:
    text = value.strip()
    parsed = urlparse.urlsplit(text)
    scheme = parsed.scheme.lower()

    if scheme in {"http", "https"}:
        if not parsed.netloc:
            raise ValueError(f"{field} must be an absolute URL")
        return "http", text

    if scheme != "unix":
        raise ValueError(f"{field} must start with http://, https://, or unix:///")

    if parsed.netloc:
        raise ValueError(f"{field} unix endpoint must not include a host")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{field} unix endpoint must not include query or fragment")
    if not parsed.path or not parsed.path.startswith("/"):
        raise ValueError(f"{field} unix endpoint must include an absolute socket path")

    normalized = f"unix://{parsed.path}"
    return "unix", normalized


def unix_socket_path_from_endpoint(value: str, *, field: str) -> str:
    transport, endpoint = normalize_mcp_endpoint(value, field=field)
    if transport != "unix":
        raise ValueError(f"{field} must be a unix:/// endpoint")
    parsed = urlparse.urlsplit(endpoint)
    return parsed.path


def maybe_parse_json_scalar(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return ""
    if stripped[0] in '{["' or stripped in {"true", "false", "null"}:
        try:
            return json5.loads(stripped)
        except Exception:
            return text
    return text
