from __future__ import annotations

from typing import Any
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
