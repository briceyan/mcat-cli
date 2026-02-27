from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .atomic_files import write_text_atomic
from .common import maybe_parse_json_scalar, read_dotenv_file


@dataclass(frozen=True, slots=True)
class KeyRef:
    kind: str
    path: str | None
    name: str | None
    raw: str


class KeyRefNotFoundError(ValueError):
    pass


def parse_key_ref(raw: str) -> KeyRef:
    value = raw.strip()
    if not value:
        raise ValueError("invalid KEY_REF: empty value")

    if value.startswith("env://"):
        name = value[len("env://") :].strip()
        if not name:
            raise ValueError("invalid KEY_REF: missing env var name")
        return KeyRef(kind="env", path=None, name=name, raw=value)

    if value.startswith(".env://"):
        rest = value[len(".env://") :]
        if ":" not in rest:
            raise ValueError("invalid KEY_REF: expected .env://path:VAR")
        path, name = rest.rsplit(":", 1)
        if not path.strip() or not name.strip():
            raise ValueError("invalid KEY_REF: expected .env://path:VAR")
        return KeyRef(kind="dotenv", path=path.strip(), name=name.strip(), raw=value)

    if value.startswith("json://"):
        path = value[len("json://") :].strip()
        if not path:
            raise ValueError("invalid KEY_REF: missing json path")
        return KeyRef(kind="json", path=path, name=None, raw=value)

    if "://" not in value:
        # Convenience shorthand: bare path means json://path.
        return KeyRef(kind="json", path=value, name=None, raw=value)

    raise ValueError("invalid KEY_REF scheme (expected env://, .env://, or json://)")


def normalize_key_ref(raw: str) -> str:
    if not raw.strip():
        raise ValueError("KEY_REF is required")
    ref = parse_key_ref(raw)
    if ref.kind == "env":
        assert ref.name is not None
        return f"env://{ref.name}"
    if ref.kind == "dotenv":
        assert ref.path is not None and ref.name is not None
        return f".env://{ref.path}:{ref.name}"
    if ref.kind == "json":
        assert ref.path is not None
        return f"json://{ref.path}"
    raise AssertionError("unreachable")


def read_key_ref_value(raw: str) -> Any:
    ref = parse_key_ref(raw)
    if ref.kind == "env":
        assert ref.name is not None
        value = os.environ.get(ref.name)
        if value is None:
            raise KeyRefNotFoundError(f"environment variable not set: {ref.name}")
        return maybe_parse_json_scalar(value)

    if ref.kind == "dotenv":
        assert ref.path is not None and ref.name is not None
        vars_map = read_dotenv_file(ref.path)
        if ref.name not in vars_map:
            raise KeyRefNotFoundError(f"variable not found in .env file: {ref.name}")
        return maybe_parse_json_scalar(vars_map[ref.name])

    if ref.kind == "json":
        assert ref.path is not None
        path = Path(ref.path)
        if not path.exists():
            raise KeyRefNotFoundError(f"json key file not found: {ref.path}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in {ref.path}: {exc.msg}") from None

    raise AssertionError("unreachable")


def write_key_ref_value(raw: str, payload: Any, *, overwrite: bool = False) -> None:
    ref = parse_key_ref(raw)
    if ref.kind == "env":
        raise ValueError(
            "env:// KEY_REF is read-only; use .env:// or json:// for output"
        )

    if ref.kind == "json":
        assert ref.path is not None
        path = Path(ref.path)
        if path.exists() and not overwrite:
            raise ValueError(
                f"json key file exists: {ref.path} (use --overwrite to replace)"
            )
        content = (
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        )
        write_text_atomic(ref.path, content)
        return

    if ref.kind == "dotenv":
        assert ref.path is not None and ref.name is not None
        if not overwrite:
            vars_map = read_dotenv_file(ref.path)
            if ref.name in vars_map:
                raise ValueError(
                    f".env key exists: {ref.name} in {ref.path} (use --overwrite to replace)"
                )
        value = (
            payload
            if isinstance(payload, str)
            else json.dumps(payload, separators=(",", ":"))
        )
        _write_dotenv_var(ref.path, ref.name, value)
        return

    raise AssertionError("unreachable")


def extract_access_token(value: Any) -> str | None:
    if isinstance(value, str):
        token = value.strip()
        return token or None
    if isinstance(value, dict):
        for key in ("access_token", "accessToken", "token"):
            token = value.get(key)
            if isinstance(token, str) and token.strip():
                return token.strip()
    return None


def _write_dotenv_var(path: str, name: str, value: str) -> None:
    file_path = Path(path)
    lines = (
        file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        if file_path.exists()
        else []
    )
    encoded_value = _dotenv_quote(value)
    new_line = f"{name}={encoded_value}\n"
    replaced = False
    out_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        candidate = stripped
        if candidate.startswith("export "):
            candidate = candidate[len("export ") :].lstrip()
        if "=" in candidate:
            key, _ = candidate.split("=", 1)
            if key.strip() == name:
                out_lines.append(new_line)
                replaced = True
                continue
        out_lines.append(line if line.endswith("\n") else f"{line}\n")
    if not replaced:
        out_lines.append(new_line)
    write_text_atomic(file_path, "".join(out_lines))


def _dotenv_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
