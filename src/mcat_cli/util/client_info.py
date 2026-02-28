from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from dataclasses_json import Undefined, dataclass_json

from .common import as_optional_str
from .key_ref import KeyRefNotFoundError, read_key_ref_value


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass(frozen=True, slots=True)
class ClientInfo:
    id: str | None = None
    secret: str | None = None
    name: str | None = None
    scope: str | None = None
    scopes: list[str] | None = None
    audience: str | None = None
    resource: str | None = None

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> ClientInfo:
        normalized_doc = dict(doc)
        if "id" not in normalized_doc and "client_id" in normalized_doc:
            normalized_doc["id"] = normalized_doc["client_id"]
        if "secret" not in normalized_doc and "client_secret" in normalized_doc:
            normalized_doc["secret"] = normalized_doc["client_secret"]
        if "name" not in normalized_doc and "client_name" in normalized_doc:
            normalized_doc["name"] = normalized_doc["client_name"]

        client_info = cast(ClientInfo, cast(Any, cls).from_dict(normalized_doc))
        client_info.validate()
        return client_info

    def to_doc(self) -> dict[str, Any]:
        return cast(dict[str, Any], cast(Any, self).to_dict())

    def validate(self) -> None:
        if self.name and (self.id or self.secret):
            raise ValueError(
                "client info file cannot combine name with id/client_id or secret/client_secret"
            )
        if self.secret and not self.id:
            raise ValueError("client info file secret/client_secret requires id/client_id")

    def resolved_scope(self) -> str | None:
        if self.scope is not None:
            return as_optional_str(self.scope)
        if isinstance(self.scopes, list):
            parts = [str(item).strip() for item in self.scopes if str(item).strip()]
            if parts:
                return " ".join(parts)
        return None

    def resolved_secret(self) -> str | None:
        if not self.secret:
            return None

        secret_spec = self.secret.strip()
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


def read_client_info(client_ref: str | None) -> ClientInfo:
    if not as_optional_str(client_ref):
        return ClientInfo()

    assert client_ref is not None
    try:
        payload = read_key_ref_value(client_ref)
    except KeyRefNotFoundError:
        raise ValueError(f"client info file not found: {client_ref}") from None

    if not isinstance(payload, dict):
        raise ValueError("client info file must contain a JSON object")

    return ClientInfo.from_doc(payload)


# Backward-compatible aliases.
def read_client_info_file(client_ref: str | None) -> ClientInfo:
    return read_client_info(client_ref)


def resolve_client_secret_spec(secret_spec: str) -> str:
    resolved = ClientInfo(secret=secret_spec).resolved_secret()
    if resolved is None:
        raise ValueError(
            f'client secret KEY_SPEC must resolve to a string or object with "secret"/"client_secret"/"value": {secret_spec}'
        )
    return resolved
