from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .common import as_optional_str
from .key_ref import KeyRefNotFoundError, read_key_ref_value


@dataclass(frozen=True, slots=True)
class ClientInfoFile:
    client_id: str | None
    client_secret_spec: str | None
    client_name: str | None
    scope: str | None
    audience: str | None
    resource: str | None


def read_client_info_file(client_ref: str | None) -> ClientInfoFile:
    client_doc = _read_client_info_doc(client_ref)
    file_id = _extract_client_alias_string(client_doc, keys=("id", "client_id"))
    file_secret_spec = _extract_client_alias_string(
        client_doc, keys=("secret", "client_secret")
    )
    file_name = _extract_client_alias_string(client_doc, keys=("name", "client_name"))
    file_scope = _coerce_scope_value(client_doc.get("scope", client_doc.get("scopes")))
    file_audience = _extract_client_alias_string(client_doc, keys=("audience",))
    file_resource = _extract_client_alias_string(client_doc, keys=("resource",))

    if file_name and (file_id or file_secret_spec):
        raise ValueError(
            "client info file cannot combine name with id/client_id or secret/client_secret"
        )
    if file_secret_spec and not file_id:
        raise ValueError("client info file secret/client_secret requires id/client_id")

    return ClientInfoFile(
        client_id=file_id,
        client_secret_spec=file_secret_spec,
        client_name=file_name,
        scope=file_scope,
        audience=file_audience,
        resource=file_resource,
    )


def resolve_client_secret_spec(secret_spec: str) -> str:
    if "://" not in secret_spec:
        return secret_spec
    try:
        payload = read_key_ref_value(secret_spec)
    except KeyRefNotFoundError:
        raise ValueError(f"client secret KEY_SPEC not found: {secret_spec}") from None
    direct = as_optional_str(payload)
    if direct:
        return direct
    if isinstance(payload, dict):
        extracted = (
            as_optional_str(payload.get("secret"))
            or as_optional_str(payload.get("client_secret"))
            or as_optional_str(payload.get("value"))
        )
        if extracted:
            return extracted
    raise ValueError(
        f"client secret KEY_SPEC must resolve to a string "
        f'or object with "secret"/"client_secret"/"value": {secret_spec}'
    )


def _read_client_info_doc(client_ref: str | None) -> dict[str, Any]:
    if not as_optional_str(client_ref):
        return {}
    assert client_ref is not None
    try:
        payload = read_key_ref_value(client_ref)
    except KeyRefNotFoundError:
        raise ValueError(f"client info file not found: {client_ref}") from None
    if not isinstance(payload, dict):
        raise ValueError("client info file must contain a JSON object")
    return payload


def _extract_client_alias_string(
    payload: dict[str, Any], *, keys: tuple[str, ...]
) -> str | None:
    for key in keys:
        value = as_optional_str(payload.get(key))
        if value:
            return value
    return None


def _coerce_scope_value(value: Any) -> str | None:
    if isinstance(value, list):
        parts = [str(x).strip() for x in value if str(x).strip()]
        return " ".join(parts) if parts else None
    if isinstance(value, str):
        return value.strip() or None
    return None
