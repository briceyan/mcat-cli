from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib import parse as urlparse


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
            return json.loads(stripped)
        except json.JSONDecodeError:
            return text
    return text


def dotenv_unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("'\"'\"'", "'")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
        if isinstance(parsed, str):
            return parsed
        return value[1:-1]
    return value


def read_dotenv_file(path: str) -> dict[str, str]:
    file_path = Path(path)
    if not file_path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        values[key] = dotenv_unquote(value.strip())
    return values
