from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import json5
from dataclasses_json import Undefined, dataclass_json

from .atomic_files import write_text_atomic
from .common import maybe_parse_json_scalar
from .env_file import read_env_file, write_env_var


@dataclass(frozen=True, slots=True)
class KeyRef:
    kind: str
    path: str | None
    name: str | None
    raw: str


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass(frozen=True, slots=True)
class WebToken:
    access_token: str
    refresh_token: str | None = None
    token_type: str | None = None
    scope: str | None = None
    expires_in: int | None = None
    expires_at: str | None = None

    @classmethod
    def from_value(cls, value: Any) -> WebToken:
        if isinstance(value, str):
            token = value.strip()
            if token:
                return cls(access_token=token)
            raise ValueError("KEY_REF does not contain an access token")

        if isinstance(value, dict):
            access_token = (
                _as_optional_str(value.get("access_token"))
                or _as_optional_str(value.get("accessToken"))
                or _as_optional_str(value.get("token"))
            )
            if not access_token:
                raise ValueError("KEY_REF does not contain an access token")
            return cls(
                access_token=access_token,
                refresh_token=_as_optional_str(value.get("refresh_token")),
                token_type=_as_optional_str(value.get("token_type")),
                scope=_as_optional_str(value.get("scope")),
                expires_in=_as_optional_int(value.get("expires_in")),
                expires_at=_as_optional_str(value.get("expires_at")),
            )

        raise ValueError("KEY_REF does not contain an access token")

    def to_json_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"access_token": self.access_token}
        if self.refresh_token is not None:
            payload["refresh_token"] = self.refresh_token
        if self.token_type is not None:
            payload["token_type"] = self.token_type
        if self.scope is not None:
            payload["scope"] = self.scope
        if self.expires_in is not None:
            payload["expires_in"] = self.expires_in
        if self.expires_at is not None:
            payload["expires_at"] = self.expires_at
        return payload

    def save(self, key_ref_spec: str, *, overwrite: bool = False) -> None:
        write_web_token(key_ref_spec, self, overwrite=overwrite)


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
        path = Path(ref.path)
        if not path.exists():
            raise KeyRefNotFoundError(f"json key file not found: {ref.path}")
        try:
            return json5.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"invalid JSON/JSON5 in {ref.path}: {exc}") from None

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
        serialized = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        write_text_atomic(ref.path, serialized)
        return

    if ref.kind == "dotenv":
        assert ref.path is not None and ref.name is not None
        if not overwrite:
            vars_map = read_env_file(ref.path)
            if ref.name in vars_map:
                raise ValueError(
                    f".env key exists: {ref.name} in {ref.path} (use --overwrite to replace)"
                )
        value = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
        write_env_var(ref.path, ref.name, value)
        return

    raise AssertionError("unreachable")


def read_web_token(raw: str) -> WebToken:
    return WebToken.from_value(read_key_ref_value(raw))


def write_web_token(raw: str, token: WebToken, *, overwrite: bool = False) -> None:
    ref = parse_key_ref(raw)
    if ref.kind == "dotenv":
        write_key_ref_value(raw, token.access_token, overwrite=overwrite)
        return
    write_key_ref_value(raw, token.to_json_payload(), overwrite=overwrite)


def extract_access_token(value: Any) -> str | None:
    try:
        return WebToken.from_value(value).access_token
    except ValueError:
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
