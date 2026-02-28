from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from .common import maybe_parse_json_scalar
from .env_file import read_env_file, write_env_var
from .json_value_file import (
    JsonValueFileNotFoundError,
    read_json_value,
    write_json_value,
)


@dataclass(frozen=True, slots=True)
class KeyRef:
    kind: str
    path: str | None
    name: str | None
    raw: str


@dataclass(frozen=True, slots=True)
class JsonTokenFile:
    access_token: str | None
    token: str | None
    refresh_token: str | None
    token_type: str | None
    scope: str | None
    expires_in: int | None
    expires_at: str | None
    raw: dict[str, Any]


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
            raise ValueError("invalid KEY_REF: expected .env://path:VAR or .env://:VAR")
        path, name = rest.rsplit(":", 1)
        dotenv_path = path.strip() or ".env"
        if not name.strip():
            raise ValueError("invalid KEY_REF: expected .env://path:VAR or .env://:VAR")
        return KeyRef(kind="dotenv", path=dotenv_path, name=name.strip(), raw=value)

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
        vars_map = read_env_file(ref.path)
        if ref.name not in vars_map:
            raise KeyRefNotFoundError(f"variable not found in .env file: {ref.name}")
        return maybe_parse_json_scalar(vars_map[ref.name])

    if ref.kind == "json":
        assert ref.path is not None
        try:
            return read_json_value(
                ref.path,
                not_found_message=f"json key file not found: {ref.path}",
                invalid_json_prefix=f"invalid JSON in {ref.path}",
            )
        except JsonValueFileNotFoundError as exc:
            raise KeyRefNotFoundError(str(exc)) from None

    raise AssertionError("unreachable")


def write_key_ref_value(raw: str, payload: Any, *, overwrite: bool = False) -> None:
    ref = parse_key_ref(raw)
    if ref.kind == "env":
        raise ValueError(
            "env:// KEY_REF is read-only; use .env:// or json:// for output"
        )

    if ref.kind == "json":
        assert ref.path is not None
        write_json_value(
            ref.path,
            payload,
            overwrite=overwrite,
            exists_message=f"json key file exists: {ref.path} (use --overwrite to replace)",
        )
        return

    if ref.kind == "dotenv":
        assert ref.path is not None and ref.name is not None
        if not overwrite:
            vars_map = read_env_file(ref.path)
            if ref.name in vars_map:
                raise ValueError(
                    f".env key exists: {ref.name} in {ref.path} (use --overwrite to replace)"
                )
        value = (
            payload
            if isinstance(payload, str)
            else json.dumps(payload, separators=(",", ":"))
        )
        write_env_var(ref.path, ref.name, value)
        return

    raise AssertionError("unreachable")


def parse_json_token_file(value: Any) -> JsonTokenFile | None:
    if not isinstance(value, dict):
        return None

    return JsonTokenFile(
        access_token=_as_optional_str(value.get("access_token"))
        or _as_optional_str(value.get("accessToken")),
        token=_as_optional_str(value.get("token")),
        refresh_token=_as_optional_str(value.get("refresh_token")),
        token_type=_as_optional_str(value.get("token_type")),
        scope=_as_optional_str(value.get("scope")),
        expires_in=_as_optional_int(value.get("expires_in")),
        expires_at=_as_optional_str(value.get("expires_at")),
        raw=dict(value),
    )


def extract_access_token(value: Any) -> str | None:
    if isinstance(value, str):
        token = value.strip()
        return token or None
    token_file = parse_json_token_file(value)
    if token_file is not None:
        return token_file.access_token or token_file.token
    return None


def _as_optional_str(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _as_optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
