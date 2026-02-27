from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from .util.auth_state import (
    default_auth_state_file as _default_auth_state_file,
)
from .util.auth_state import (
    read_auth_state_file as _read_auth_state_file,
)
from .util.auth_state import (
    write_auth_state_file as _write_auth_state_file,
)
from .util.common import (
    as_optional_str as _as_optional_str,
)
from .util.common import (
    normalize_url as _normalize_url,
)
from .util.key_ref import (
    KeyRefNotFoundError,
)
from .util.key_ref import (
    extract_access_token as _extract_access_token,
)
from .util.key_ref import (
    read_key_ref_value as _read_key_ref,
)
from .util.key_ref import (
    write_key_ref_value as _write_key_ref,
)

LOGGER = logging.getLogger("mcat.auth")

DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
DEFAULT_PUBLIC_CLIENT_ID = "mcat-cli"
AUTH_CODE_TIMEOUT_S = 300.0


@dataclass(frozen=True, slots=True)
class ClientConfig:
    client_id: str
    client_secret: str | None
    scope: str | None
    audience: str | None
    resource: str | None


@dataclass(frozen=True, slots=True)
class AuthChallenge:
    scheme: str
    params: dict[str, str]


@dataclass(slots=True)
class OAuthCallbackServerHandle:
    server: ThreadingHTTPServer
    thread: threading.Thread
    event: threading.Event
    result: dict[str, str | None]
    expected_state: str
    callback_path: str
    redirect_uri: str


class HttpJsonError(RuntimeError):
    def __init__(
        self,
        *,
        status: int,
        url: str,
        body_text: str,
        payload: Any | None,
    ) -> None:
        self.status = status
        self.url = url
        self.body_text = body_text
        self.payload = payload
        super().__init__(f"HTTP {status} for {url}")


def start_auth(
    *,
    endpoint: str,
    key_ref: str,
    state_file: str | None,
    wait: bool,
    overwrite: bool,
) -> dict[str, Any]:
    LOGGER.info("auth.start endpoint=%s wait=%s", endpoint, wait)
    endpoint = _normalize_url(endpoint, field="ENDPOINT")
    existing = _existing_valid_token_result(endpoint=endpoint, key_ref=key_ref)
    if existing is not None:
        return existing

    client_cfg = _load_client_config_from_key_ref(key_ref)
    oauth_meta = _discover_oauth_metadata(endpoint)
    if _as_optional_str(oauth_meta.get("device_authorization_endpoint")):
        return _start_auth_device(
            endpoint=endpoint,
            key_ref=key_ref,
            state_file=state_file,
            wait=wait,
            overwrite=overwrite,
            client_cfg=client_cfg,
            oauth_meta=oauth_meta,
        )

    if _as_optional_str(oauth_meta.get("authorization_endpoint")) and _as_optional_str(
        oauth_meta.get("token_endpoint")
    ):
        return _start_auth_authorization_code(
            endpoint=endpoint,
            key_ref=key_ref,
            state_file=state_file,
            wait=wait,
            overwrite=overwrite,
            client_cfg=client_cfg,
            oauth_meta=oauth_meta,
        )

    raise ValueError("unable to discover a supported OAuth login flow")


def _existing_valid_token_result(*, endpoint: str, key_ref: str) -> dict[str, Any] | None:
    token = _read_access_token_from_key_ref(key_ref)
    if token is None:
        return None
    if not _is_token_valid_for_endpoint(endpoint=endpoint, token=token):
        return None
    LOGGER.info("auth.start token already valid; skipping authorization")
    return {"status": "complete", "stored": key_ref, "already_valid": True}


def _read_access_token_from_key_ref(key_ref_raw: str) -> str | None:
    try:
        payload = _read_key_ref(key_ref_raw)
    except KeyRefNotFoundError:
        return None
    return _extract_access_token(payload)


def _is_token_valid_for_endpoint(*, endpoint: str, token: str) -> bool:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "mcat-cli", "version": "0.1.0"},
        },
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {
        "User-Agent": "mcat-cli/0.1",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    LOGGER.info("auth.token.check endpoint=%s", endpoint)
    req = urlrequest.Request(url=endpoint, method="POST", data=body, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=30.0) as resp:
            status = int(getattr(resp, "status", 200))
            text = resp.read().decode("utf-8", errors="replace")
    except urlerror.HTTPError as exc:
        status = int(exc.code)
        text = exc.read().decode("utf-8", errors="replace")
        LOGGER.info("auth.token.check endpoint=%s -> %s", endpoint, status)
        if status in {401, 403}:
            return False
        return not _contains_auth_failure_text(text)
    except urlerror.URLError as exc:
        reason = getattr(exc, "reason", exc)
        LOGGER.info("auth.token.check endpoint=%s err=%s", endpoint, reason)
        return False

    LOGGER.info("auth.token.check endpoint=%s -> %s", endpoint, status)
    if not 200 <= status < 300:
        return False
    return not _contains_auth_failure_text(text)


def _contains_auth_failure_text(text: str) -> bool:
    lowered = text.lower()
    return any(
        marker in lowered
        for marker in (
            "unauthorized",
            "invalid token",
            "invalid_token",
            "authentication failed",
            "access denied",
            "forbidden",
        )
    )


def continue_auth(
    *,
    state_file: str,
    key_ref: str,
    overwrite: bool,
) -> dict[str, Any]:
    LOGGER.info("auth.continue state_file=%s", state_file)
    state_path = Path(state_file)
    if not state_path.exists():
        raise ValueError(f"auth state file not found: {state_file}")

    state_doc = _read_auth_state_file(state_file)
    state = state_doc.get("state")
    if not isinstance(state, dict):
        raise ValueError("invalid auth state file: missing state object")
    flow = _as_optional_str(state_doc.get("flow"))
    if flow == "device_code":
        return _continue_auth_device(
            state_file=state_file,
            state_doc=state_doc,
            state=state,
            key_ref=key_ref,
            overwrite=overwrite,
        )
    if flow == "authorization_code":
        return _continue_auth_authorization_code(
            state_file=state_file,
            state_doc=state_doc,
            state=state,
            key_ref=key_ref,
            overwrite=overwrite,
        )
    raise ValueError("unsupported auth state flow")


def _start_auth_device(
    *,
    endpoint: str,
    key_ref: str,
    state_file: str | None,
    wait: bool,
    overwrite: bool,
    client_cfg: ClientConfig,
    oauth_meta: dict[str, str],
) -> dict[str, Any]:
    device_flow = _start_device_code_flow(
        oauth_meta=oauth_meta,
        client_cfg=client_cfg,
    )

    resolved_state_file = (
        state_file or _default_auth_state_file() if not wait else state_file
    )
    state_doc = _build_auth_state_doc(
        endpoint=endpoint,
        input_key_ref=key_ref,
        oauth_meta=oauth_meta,
        client_cfg=client_cfg,
        device_flow=device_flow,
    )

    if resolved_state_file:
        _write_auth_state_file(resolved_state_file, state_doc)

    if wait:
        _print_wait_instructions(device_flow)
        token_payload = _poll_until_complete(
            state_doc["state"],
            rewrite_state=(resolved_state_file, state_doc)
            if resolved_state_file
            else None,
        )
        return _finalize_token_result(
            token_payload,
            key_ref=key_ref,
            overwrite=overwrite,
        )

    return _pending_result(
        state_file=_require_state_file_for_pending(resolved_state_file),
        state=state_doc["state"],
    )


def _continue_auth_device(
    *,
    state_file: str,
    state_doc: dict[str, Any],
    state: dict[str, Any],
    key_ref: str,
    overwrite: bool,
) -> dict[str, Any]:
    poll = _poll_token_once(state)
    if poll["status"] == "pending":
        _write_auth_state_file(state_file, state_doc)
        return _pending_result(state_file=state_file, state=state)

    if poll["status"] != "complete":
        raise ValueError("unexpected auth poll result")

    token_payload = poll["token"]
    state["status"] = "complete"
    state["completed_at"] = _now_epoch()
    _write_auth_state_file(state_file, state_doc)
    return _finalize_token_result(
        token_payload,
        key_ref=key_ref,
        overwrite=overwrite,
    )


def _start_auth_authorization_code(
    *,
    endpoint: str,
    key_ref: str,
    state_file: str | None,
    wait: bool,
    overwrite: bool,
    client_cfg: ClientConfig,
    oauth_meta: dict[str, str],
) -> dict[str, Any]:
    if not wait:
        raise ValueError(
            "authorization_code flow is supported only with --wait in this build"
        )

    authz_endpoint = _as_optional_str(oauth_meta.get("authorization_endpoint"))
    token_endpoint = _as_optional_str(oauth_meta.get("token_endpoint"))
    if not authz_endpoint or not token_endpoint:
        raise ValueError("authorization_code flow metadata is incomplete")

    state_nonce = secrets.token_urlsafe(24)
    callback = _start_oauth_callback_listener(None, state_nonce)
    try:
        registration = _resolve_client_for_authorization_code(
            oauth_meta=oauth_meta,
            client_cfg=client_cfg,
            redirect_uri=callback.redirect_uri,
        )

        code_verifier = _generate_pkce_verifier()
        code_challenge = _pkce_challenge_s256(code_verifier)
        auth_url = _build_authorization_request_url(
            authorization_endpoint=authz_endpoint,
            client_id=registration["client_id"],
            redirect_uri=callback.redirect_uri,
            state=state_nonce,
            code_challenge=code_challenge,
            scope=_as_optional_str(oauth_meta.get("challenged_scope"))
            or client_cfg.scope,
            resource=_as_optional_str(oauth_meta.get("resource"))
            or client_cfg.resource,
        )

        state_doc = _build_auth_code_state_doc(
            endpoint=endpoint,
            input_key_ref=key_ref,
            oauth_meta=oauth_meta,
            client_id=registration["client_id"],
            client_secret=registration.get("client_secret"),
            redirect_uri=callback.redirect_uri,
            code_verifier=code_verifier,
            oauth_state=state_nonce,
            authorization_url=auth_url,
        )
        if state_file:
            _write_auth_state_file(state_file, state_doc)

        _print_wait_instructions({"verification_uri_complete": auth_url})
        callback_result = _wait_for_oauth_callback(
            callback, timeout_s=AUTH_CODE_TIMEOUT_S
        )
        token_payload = _exchange_authorization_code(
            token_endpoint=token_endpoint,
            code=callback_result["code"],
            client_id=registration["client_id"],
            client_secret=registration.get("client_secret"),
            redirect_uri=callback.redirect_uri,
            code_verifier=code_verifier,
            resource=_as_optional_str(oauth_meta.get("resource"))
            or client_cfg.resource,
        )

        if state_file:
            state_doc["state"]["status"] = "complete"
            state_doc["state"]["completed_at"] = _now_epoch()
            _write_auth_state_file(state_file, state_doc)
        return _finalize_token_result(
            token_payload,
            key_ref=key_ref,
            overwrite=overwrite,
        )
    except TimeoutError:
        raise ValueError(
            "timed out waiting for OAuth callback (re-run `mcat auth start` or use `mcat auth continue`)"
        ) from None
    finally:
        _stop_oauth_callback_listener(callback)


def _continue_auth_authorization_code(
    *,
    state_file: str,
    state_doc: dict[str, Any],
    state: dict[str, Any],
    key_ref: str,
    overwrite: bool,
) -> dict[str, Any]:
    # Resume by re-opening the same loopback callback listener and waiting for completion.
    redirect_uri = _require_state_str(state, "redirect_uri")
    oauth_state = _require_state_str(state, "oauth_state")
    authorization_url = _require_state_str(state, "authorization_url")
    callback = _start_oauth_callback_listener(redirect_uri, oauth_state)
    if callback.redirect_uri != redirect_uri:
        _stop_oauth_callback_listener(callback)
        raise ValueError(
            f"unable to bind saved redirect URI {redirect_uri}; ensure the port is free"
        )
    try:
        _print_wait_instructions({"verification_uri_complete": authorization_url})
        callback_result = _wait_for_oauth_callback(
            callback, timeout_s=AUTH_CODE_TIMEOUT_S
        )
        token_payload = _exchange_authorization_code(
            token_endpoint=_require_state_str(state, "token_endpoint"),
            code=callback_result["code"],
            client_id=_require_state_str(state, "client_id"),
            client_secret=_as_optional_str(state.get("client_secret")),
            redirect_uri=redirect_uri,
            code_verifier=_require_state_str(state, "code_verifier"),
            resource=_as_optional_str(state.get("resource")),
        )
        state["status"] = "complete"
        state["completed_at"] = _now_epoch()
        _write_auth_state_file(state_file, state_doc)
        return _finalize_token_result(
            token_payload,
            key_ref=key_ref,
            overwrite=overwrite,
        )
    except TimeoutError:
        _write_auth_state_file(state_file, state_doc)
        raise ValueError("timed out waiting for OAuth callback") from None
    finally:
        _stop_oauth_callback_listener(callback)


def _pending_result(*, state_file: str, state: dict[str, Any]) -> dict[str, Any]:
    action: dict[str, Any] = {}
    if _as_optional_str(state.get("verification_uri_complete")):
        action["url"] = state["verification_uri_complete"]
    elif _as_optional_str(state.get("verification_uri")):
        action["url"] = state["verification_uri"]

    if _as_optional_str(state.get("user_code")):
        action["code"] = state["user_code"]

    result: dict[str, Any] = {
        "status": "pending",
        "state_file": state_file,
        "action": action,
    }
    return result


def _finalize_token_result(
    token_payload: dict[str, Any], *, key_ref: str, overwrite: bool
) -> dict[str, Any]:
    normalized = _normalize_token_payload(token_payload)
    _write_key_ref(key_ref, normalized, overwrite=overwrite)
    return {"status": "complete", "stored": key_ref}


def _normalize_token_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    expires_in = normalized.get("expires_in")
    if "expires_at" not in normalized and isinstance(expires_in, (int, float)):
        normalized["expires_at"] = _iso_utc(int(_now_epoch() + float(expires_in)))
    return normalized


def _build_auth_state_doc(
    *,
    endpoint: str,
    input_key_ref: str,
    oauth_meta: dict[str, str],
    client_cfg: ClientConfig,
    device_flow: dict[str, Any],
) -> dict[str, Any]:
    expires_in = _as_int(device_flow.get("expires_in")) or 900
    interval = _as_int(device_flow.get("interval")) or 5
    state: dict[str, Any] = {
        "issuer": oauth_meta["issuer"],
        "token_endpoint": oauth_meta["token_endpoint"],
        "device_authorization_endpoint": oauth_meta["device_authorization_endpoint"],
        "client_id": client_cfg.client_id,
        "interval": interval,
        "expires_at": _now_epoch() + expires_in,
        "device_code": device_flow.get("device_code"),
        "user_code": device_flow.get("user_code"),
        "verification_uri": device_flow.get("verification_uri"),
        "verification_uri_complete": device_flow.get("verification_uri_complete"),
        "input_key_ref": input_key_ref,
        "status": "pending",
    }
    if client_cfg.client_secret:
        state["client_secret"] = client_cfg.client_secret
    if client_cfg.scope:
        state["scope"] = client_cfg.scope
    if client_cfg.audience:
        state["audience"] = client_cfg.audience
    if client_cfg.resource:
        state["resource"] = client_cfg.resource

    return {
        "version": 1,
        "endpoint": endpoint,
        "flow": "device_code",
        "state": state,
    }


def _poll_until_complete(
    state: dict[str, Any],
    *,
    rewrite_state: tuple[str, dict[str, Any]] | None,
) -> dict[str, Any]:
    while True:
        poll = _poll_token_once(state)
        if poll["status"] == "complete":
            state["status"] = "complete"
            state["completed_at"] = _now_epoch()
            if rewrite_state:
                _write_auth_state_file(rewrite_state[0], rewrite_state[1])
            return poll["token"]

        if poll["status"] != "pending":
            raise ValueError("unexpected auth poll status")

        if rewrite_state:
            _write_auth_state_file(rewrite_state[0], rewrite_state[1])

        now = _now_epoch()
        expires_at = _as_int(state.get("expires_at")) or 0
        if expires_at and now >= expires_at:
            raise ValueError("device authorization expired")

        interval = _as_int(state.get("interval")) or 5
        sleep_for = max(1, interval)
        LOGGER.info("auth.poll pending; sleeping %ss", sleep_for)
        time.sleep(sleep_for)


def _poll_token_once(state: dict[str, Any]) -> dict[str, Any]:
    token_endpoint = _require_state_str(state, "token_endpoint")
    device_code = _require_state_str(state, "device_code")
    client_id = _require_state_str(state, "client_id")
    client_secret = _as_optional_str(state.get("client_secret"))

    form: dict[str, str] = {
        "grant_type": DEVICE_GRANT_TYPE,
        "device_code": device_code,
        "client_id": client_id,
    }
    if client_secret:
        form["client_secret"] = client_secret

    # Common provider-specific fields some servers require/accept.
    if _as_optional_str(state.get("scope")):
        form["scope"] = state["scope"]
    if _as_optional_str(state.get("audience")):
        form["audience"] = state["audience"]
    if _as_optional_str(state.get("resource")):
        form["resource"] = state["resource"]

    try:
        token = _http_json(
            "POST",
            token_endpoint,
            form=form,
            extra_headers={"Accept": "application/json"},
        )
    except HttpJsonError as exc:
        payload = exc.payload if isinstance(exc.payload, dict) else {}
        oauth_error = str(payload.get("error") or "")
        description = _as_optional_str(payload.get("error_description"))

        if oauth_error == "authorization_pending":
            return {"status": "pending"}

        if oauth_error == "slow_down":
            current = _as_int(state.get("interval")) or 5
            state["interval"] = current + 5
            return {"status": "pending"}

        if oauth_error in {"expired_token", "access_denied"}:
            msg = description or oauth_error.replace("_", " ")
            raise ValueError(f"device authorization failed: {msg}")

        if oauth_error:
            msg = description or oauth_error
            raise ValueError(f"token request failed: {msg}")

        raise ValueError(f"token request failed (HTTP {exc.status})")

    if not isinstance(token, dict):
        raise ValueError("invalid token response")
    if "access_token" not in token:
        raise ValueError("token response missing access_token")
    return {"status": "complete", "token": token}


def _start_device_code_flow(
    *,
    oauth_meta: dict[str, str],
    client_cfg: ClientConfig,
) -> dict[str, Any]:
    form: dict[str, str] = {"client_id": client_cfg.client_id}
    if client_cfg.client_secret:
        form["client_secret"] = client_cfg.client_secret
    if client_cfg.scope:
        form["scope"] = client_cfg.scope
    if client_cfg.audience:
        form["audience"] = client_cfg.audience
    if client_cfg.resource:
        form["resource"] = client_cfg.resource

    try:
        resp = _http_json(
            "POST",
            oauth_meta["device_authorization_endpoint"],
            form=form,
            extra_headers={"Accept": "application/json"},
        )
    except HttpJsonError as exc:
        payload = exc.payload if isinstance(exc.payload, dict) else {}
        msg = _as_optional_str(payload.get("error_description")) or _as_optional_str(
            payload.get("error")
        )
        if msg:
            raise ValueError(f"device authorization request failed: {msg}") from None
        raise ValueError(
            f"device authorization request failed (HTTP {exc.status})"
        ) from None

    if not isinstance(resp, dict):
        raise ValueError("invalid device authorization response")
    for key in ("device_code", "user_code"):
        if not _as_optional_str(resp.get(key)):
            raise ValueError(f"device authorization response missing {key}")
    if not (
        _as_optional_str(resp.get("verification_uri"))
        or _as_optional_str(resp.get("verification_uri_complete"))
    ):
        raise ValueError(
            "device authorization response missing verification_uri/verification_uri_complete"
        )
    return resp


def _resolve_client_for_authorization_code(
    *,
    oauth_meta: dict[str, str],
    client_cfg: ClientConfig,
    redirect_uri: str,
) -> dict[str, str]:
    registration_endpoint = _as_optional_str(oauth_meta.get("registration_endpoint"))
    if (
        registration_endpoint is not None
        and client_cfg.client_id == DEFAULT_PUBLIC_CLIENT_ID
        and client_cfg.client_secret is None
    ):
        reg = _register_dynamic_client(
            registration_endpoint=registration_endpoint,
            redirect_uri=redirect_uri,
            client_name="mcat-cli",
        )
        client_id = _as_optional_str(reg.get("client_id"))
        if not client_id:
            raise ValueError("dynamic client registration returned no client_id")
        result = {"client_id": client_id}
        client_secret = _as_optional_str(reg.get("client_secret"))
        if client_secret:
            result["client_secret"] = client_secret
        return result

    return {
        "client_id": client_cfg.client_id,
        **(
            {"client_secret": client_cfg.client_secret}
            if client_cfg.client_secret
            else {}
        ),
    }


def _register_dynamic_client(
    *,
    registration_endpoint: str,
    redirect_uri: str,
    client_name: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "client_name": client_name,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "redirect_uris": [redirect_uri],
    }
    try:
        resp = _http_json(
            "POST",
            registration_endpoint,
            json_body=payload,
            extra_headers={"Accept": "application/json"},
        )
    except HttpJsonError as exc:
        payload_obj = exc.payload if isinstance(exc.payload, dict) else {}
        msg = _as_optional_str(
            payload_obj.get("error_description")
        ) or _as_optional_str(payload_obj.get("error"))
        if msg:
            raise ValueError(f"dynamic client registration failed: {msg}") from None
        raise ValueError(
            f"dynamic client registration failed (HTTP {exc.status})"
        ) from None
    if not isinstance(resp, dict):
        raise ValueError("invalid dynamic client registration response")
    return resp


def _build_auth_code_state_doc(
    *,
    endpoint: str,
    input_key_ref: str,
    oauth_meta: dict[str, str],
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
    code_verifier: str,
    oauth_state: str,
    authorization_url: str,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "issuer": _require_state_like(oauth_meta, "issuer"),
        "authorization_endpoint": _require_state_like(
            oauth_meta, "authorization_endpoint"
        ),
        "token_endpoint": _require_state_like(oauth_meta, "token_endpoint"),
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "oauth_state": oauth_state,
        "authorization_url": authorization_url,
        "input_key_ref": input_key_ref,
        "status": "pending",
    }
    if client_secret:
        state["client_secret"] = client_secret
    if _as_optional_str(oauth_meta.get("resource")):
        state["resource"] = oauth_meta["resource"]
    if _as_optional_str(oauth_meta.get("challenged_scope")):
        state["scope"] = oauth_meta["challenged_scope"]
    return {
        "version": 1,
        "endpoint": endpoint,
        "flow": "authorization_code",
        "state": state,
    }


def _generate_pkce_verifier() -> str:
    return _b64url(secrets.token_bytes(32))


def _pkce_challenge_s256(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _build_authorization_request_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scope: str | None,
    resource: str | None,
) -> str:
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if scope:
        params["scope"] = scope
    if resource:
        params["resource"] = resource
    sep = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{sep}{urlparse.urlencode(params)}"


def _start_oauth_callback_listener(
    redirect_uri: str | None,
    expected_state: str,
) -> OAuthCallbackServerHandle:
    if not redirect_uri:
        redirect_uri = "http://127.0.0.1:0/callback"

    parts = urlparse.urlsplit(redirect_uri)
    if parts.scheme != "http" or parts.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError(
            "redirect_uri must be local http://127.0.0.1:<port>/... or http://localhost:<port>/..."
        )

    callback_path = parts.path or "/"
    bind_port = parts.port or 0
    host = parts.hostname or "127.0.0.1"
    result: dict[str, str | None] = {
        "code": None,
        "state": None,
        "error": None,
        "error_description": None,
    }
    event = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            req = urlparse.urlsplit(self.path)
            if req.path != callback_path:
                self.send_response(404)
                self.end_headers()
                return
            qs = urlparse.parse_qs(req.query)
            result["code"] = (qs.get("code") or [None])[0]
            result["state"] = (qs.get("state") or [None])[0]
            result["error"] = (qs.get("error") or [None])[0]
            result["error_description"] = (qs.get("error_description") or [None])[0]
            ok = result["state"] == expected_state and bool(result["code"])
            body = (
                b"Authentication complete. You can close this window.\n"
                if ok
                else b"Authentication failed or invalid callback state.\n"
            )
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            event.set()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer((host, bind_port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    actual_port = server.server_address[1]
    effective_redirect = urlparse.urlunsplit(
        ("http", f"{host}:{actual_port}", callback_path, "", "")
    )
    LOGGER.info("auth.callback_listener started redirect_uri=%s", effective_redirect)
    return OAuthCallbackServerHandle(
        server=server,
        thread=thread,
        event=event,
        result=result,
        expected_state=expected_state,
        callback_path=callback_path,
        redirect_uri=effective_redirect,
    )


def _wait_for_oauth_callback(
    handle: OAuthCallbackServerHandle,
    *,
    timeout_s: float,
) -> dict[str, str]:
    if not handle.event.wait(timeout_s):
        raise TimeoutError(
            f"timed out waiting for OAuth callback on {handle.redirect_uri}"
        )

    callback_state = handle.result.get("state")
    callback_error = handle.result.get("error")
    callback_error_description = handle.result.get("error_description")
    callback_code = handle.result.get("code")

    if callback_error:
        msg = callback_error
        if callback_error_description:
            msg = f"{msg}: {callback_error_description}"
        raise ValueError(f"authorization failed: {msg}")
    if callback_state != handle.expected_state:
        raise ValueError("OAuth callback state mismatch")
    if not callback_code:
        raise ValueError("OAuth callback missing authorization code")
    return {"code": callback_code}


def _stop_oauth_callback_listener(handle: OAuthCallbackServerHandle) -> None:
    try:
        handle.server.shutdown()
        handle.server.server_close()
    finally:
        handle.thread.join(timeout=2.0)
        LOGGER.info(
            "auth.callback_listener stopped redirect_uri=%s", handle.redirect_uri
        )


def _exchange_authorization_code(
    *,
    token_endpoint: str,
    code: str,
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
    code_verifier: str,
    resource: str | None,
) -> dict[str, Any]:
    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if client_secret:
        form["client_secret"] = client_secret
    if resource:
        form["resource"] = resource
    try:
        resp = _http_json(
            "POST",
            token_endpoint,
            form=form,
            extra_headers={"Accept": "application/json"},
        )
    except HttpJsonError as exc:
        payload = exc.payload if isinstance(exc.payload, dict) else {}
        msg = _as_optional_str(payload.get("error_description")) or _as_optional_str(
            payload.get("error")
        )
        if msg:
            raise ValueError(f"token exchange failed: {msg}") from None
        raise ValueError(f"token exchange failed (HTTP {exc.status})") from None
    if not isinstance(resp, dict):
        raise ValueError("invalid token exchange response")
    if "access_token" not in resp:
        raise ValueError("token exchange response missing access_token")
    return resp


def _discover_oauth_metadata(endpoint: str) -> dict[str, str]:
    probe = _probe_mcp_auth(endpoint)

    issuer_candidates: list[str] = []
    resource_candidates: list[str] = []
    discovered_resource: str | None = None

    hinted_resource_metadata = probe.get("resource_metadata")
    if isinstance(hinted_resource_metadata, str) and hinted_resource_metadata.strip():
        resource_candidates.append(hinted_resource_metadata.strip())

    resource_candidates.extend(_protected_resource_metadata_urls(endpoint))

    for url in _dedupe(resource_candidates):
        try:
            meta = _http_json("GET", url)
        except Exception as exc:
            LOGGER.info(
                "auth.discovery protected-resource miss url=%s err=%s", url, exc
            )
            continue
        if isinstance(meta, dict):
            if not discovered_resource:
                discovered_resource = _as_optional_str(meta.get("resource"))
            servers = meta.get("authorization_servers")
            if isinstance(servers, list):
                issuer_candidates.extend(
                    s for s in servers if isinstance(s, str) and s.strip()
                )
                if issuer_candidates:
                    break

    hinted_issuer = probe.get("authorization_server")
    if isinstance(hinted_issuer, str) and hinted_issuer.strip():
        issuer_candidates.append(hinted_issuer.strip())

    if not issuer_candidates:
        issuer_candidates.append(endpoint)
        host_issuer = _mcp_host_issuer(endpoint)
        if host_issuer:
            issuer_candidates.append(host_issuer)
    else:
        host_issuer = _mcp_host_issuer(endpoint)
        if host_issuer:
            issuer_candidates.append(host_issuer)

    seen: set[str] = set()
    found_auth_server_without_supported_flow = False
    for issuer in issuer_candidates:
        issuer = issuer.rstrip("/")
        if not issuer or issuer in seen:
            continue
        seen.add(issuer)
        for url in _authorization_server_metadata_urls(issuer):
            try:
                meta = _http_json("GET", url)
            except Exception as exc:
                LOGGER.info("auth.discovery auth-server miss url=%s err=%s", url, exc)
                continue
            if not isinstance(meta, dict):
                continue
            token_endpoint = _as_optional_str(meta.get("token_endpoint"))
            authorization_endpoint = _as_optional_str(
                meta.get("authorization_endpoint")
            )
            device_endpoint = _as_optional_str(
                meta.get("device_authorization_endpoint")
            ) or _as_optional_str(
                meta.get("device_authorization_endpoint".replace("_", "-"))
            )
            registration_endpoint = _as_optional_str(meta.get("registration_endpoint"))
            issuer_from_meta = _as_optional_str(meta.get("issuer")) or issuer
            if token_endpoint and not (device_endpoint or authorization_endpoint):
                found_auth_server_without_supported_flow = True
                LOGGER.info(
                    "auth.discovery auth-server found issuer=%s but no supported login endpoint",
                    issuer_from_meta,
                )
            if token_endpoint and (device_endpoint or authorization_endpoint):
                result: dict[str, str] = {
                    "issuer": issuer_from_meta,
                    "token_endpoint": token_endpoint,
                }
                if device_endpoint:
                    result["device_authorization_endpoint"] = device_endpoint
                if authorization_endpoint:
                    result["authorization_endpoint"] = authorization_endpoint
                if registration_endpoint:
                    result["registration_endpoint"] = registration_endpoint
                challenged_scope = _as_optional_str(probe.get("challenged_scope"))
                if challenged_scope:
                    result["challenged_scope"] = challenged_scope
                if discovered_resource:
                    result["resource"] = discovered_resource
                return result

    if found_auth_server_without_supported_flow:
        raise ValueError(
            "OAuth authorization server metadata found, but no supported login endpoint"
        )
    raise ValueError("unable to discover OAuth authorization endpoints")


def _protected_resource_metadata_urls(endpoint: str) -> list[str]:
    parsed = urlparse.urlsplit(endpoint)
    if not parsed.scheme or not parsed.netloc:
        return []

    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.strip("/")
    urls: list[str] = []
    if path:
        urls.append(f"{base}/.well-known/oauth-protected-resource/{path}")
    urls.append(f"{base}/.well-known/oauth-protected-resource")
    return _dedupe(urls)


def _authorization_server_metadata_urls(issuer: str) -> list[str]:
    issuer = issuer.rstrip("/")
    parsed = urlparse.urlsplit(issuer)
    if not parsed.scheme or not parsed.netloc:
        return []

    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.strip("/")
    urls: list[str] = []
    if path:
        urls.append(f"{base}/.well-known/oauth-authorization-server/{path}")
        urls.append(f"{base}/.well-known/openid-configuration/{path}")
        urls.append(f"{issuer}/.well-known/oauth-authorization-server")
        urls.append(f"{issuer}/.well-known/openid-configuration")
    else:
        urls.append(f"{issuer}/.well-known/oauth-authorization-server")
        urls.append(f"{issuer}/.well-known/openid-configuration")
    # Some servers expose metadata directly at the issuer URL.
    urls.append(issuer)
    return _dedupe(urls)


def _mcp_host_issuer(endpoint: str) -> str | None:
    parsed = urlparse.urlsplit(endpoint)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _probe_mcp_auth(endpoint: str) -> dict[str, str]:
    probe_json = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "mcat-cli", "version": "0.1.0"},
        },
    }
    body = json.dumps(probe_json, separators=(",", ":")).encode("utf-8")
    headers = {
        "User-Agent": "mcat-cli/0.1",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    LOGGER.info("auth.http POST %s jsonrpc=initialize", endpoint)
    req = urlrequest.Request(url=endpoint, method="POST", data=body, headers=headers)
    resp_headers = None
    status: int | None = None
    text = ""
    try:
        with urlrequest.urlopen(req, timeout=30.0) as resp:
            status = int(getattr(resp, "status", 200))
            resp_headers = resp.headers
            text = resp.read().decode("utf-8", errors="replace")
    except urlerror.HTTPError as exc:
        status = int(exc.code)
        resp_headers = exc.headers
        text = exc.read().decode("utf-8", errors="replace")
    except urlerror.URLError as exc:
        reason = getattr(exc, "reason", exc)
        LOGGER.info(
            "auth.discovery mcp-probe miss endpoint=%s err=%s", endpoint, reason
        )
        return {}

    LOGGER.info("auth.http POST %s -> %s", endpoint, status)
    www_auth_values = _get_header_values(resp_headers, "WWW-Authenticate")
    challenges = _parse_www_authenticate(www_auth_values)
    bearer = next((c for c in challenges if c.scheme == "bearer"), None)
    if bearer is None:
        return {}

    if www_auth_values:
        LOGGER.info(
            "auth.discovery mcp-probe bearer params=%s",
            ",".join(sorted(bearer.params)),
        )
    if text:
        # Keep body logging concise; this is mainly useful for debugging non-standard servers.
        LOGGER.debug("auth.discovery mcp-probe body=%s", text[:500])

    out: dict[str, str] = {}
    resource_metadata = bearer.params.get("resource_metadata")
    if resource_metadata:
        out["resource_metadata"] = resource_metadata
    authorization_server = bearer.params.get("authorization_server")
    if authorization_server:
        out["authorization_server"] = authorization_server
    challenged_scope = bearer.params.get("scope")
    if challenged_scope:
        out["challenged_scope"] = challenged_scope
    return out


def _http_json(
    method: str,
    url: str,
    *,
    form: dict[str, str] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout_s: float = 30.0,
) -> Any:
    if form is not None and json_body is not None:
        raise ValueError("internal error: form and json_body are mutually exclusive")
    headers = {
        "User-Agent": "mcat-cli/0.1",
    }
    data: bytes | None = None
    if form is not None:
        data = urlparse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        LOGGER.info(
            "auth.http %s %s form_keys=%s",
            method,
            url,
            ",".join(sorted(form)),
        )
    elif json_body is not None:
        data = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
        LOGGER.info("auth.http %s %s json", method, url)
    else:
        LOGGER.info("auth.http %s %s", method, url)

    if extra_headers:
        headers.update(extra_headers)

    req = urlrequest.Request(url=url, method=method, data=data, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=timeout_s) as resp:
            status = getattr(resp, "status", 200)
            body = resp.read()
            text = body.decode("utf-8", errors="replace")
            LOGGER.info("auth.http %s %s -> %s", method, url, status)
            if not text:
                return None
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                raise ValueError(f"invalid JSON response from {url}") from None
    except urlerror.HTTPError as exc:
        body = exc.read()
        text = body.decode("utf-8", errors="replace")
        payload: Any | None = None
        try:
            payload = json.loads(text) if text else None
        except json.JSONDecodeError:
            payload = None
        LOGGER.info("auth.http %s %s -> %s", method, url, exc.code)
        raise HttpJsonError(
            status=int(exc.code),
            url=url,
            body_text=text,
            payload=payload,
        ) from None
    except urlerror.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ValueError(f"network error contacting {url}: {reason}") from None


def _get_header_values(headers: Any, name: str) -> list[str]:
    if headers is None:
        return []
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name)
        if values:
            return [str(v) for v in values if v is not None]
    getheaders = getattr(headers, "getheaders", None)
    if callable(getheaders):
        values = getheaders(name)
        if values:
            return [str(v) for v in values if v is not None]
    get = getattr(headers, "get", None)
    if callable(get):
        value = get(name)
        if value:
            return [str(value)]
    return []


def _parse_www_authenticate(headers: list[str] | str | None) -> list[AuthChallenge]:
    if headers is None:
        return []
    values = [headers] if isinstance(headers, str) else headers
    challenges: list[AuthChallenge] = []

    for value in values:
        current_scheme: str | None = None
        current_params: dict[str, str] = {}
        for part in _split_quoted_commas(value):
            token, _, rest = part.partition(" ")
            starts_new = bool(rest) and "=" not in token
            if starts_new:
                if current_scheme is not None:
                    challenges.append(AuthChallenge(current_scheme, current_params))
                current_scheme = token.lower()
                current_params = _parse_param_fragment(rest)
                continue

            if current_scheme is None:
                if "=" not in part and part:
                    current_scheme = part.lower()
                    current_params = {}
                continue

            current_params.update(_parse_param_fragment(part))

        if current_scheme is not None:
            challenges.append(AuthChallenge(current_scheme, current_params))

    return challenges


def _split_quoted_commas(value: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escaped = False
    for ch in value:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_quotes:
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            buf.append(ch)
            in_quotes = not in_quotes
            continue
        if ch == "," and not in_quotes:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(ch)
    part = "".join(buf).strip()
    if part:
        parts.append(part)
    return parts


def _parse_param_fragment(fragment: str) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 0
    n = len(fragment)
    while i < n:
        while i < n and (fragment[i].isspace() or fragment[i] == ","):
            i += 1
        j = i
        while j < n and (fragment[j].isalnum() or fragment[j] in "-_"):
            j += 1
        if j == i:
            break
        key = fragment[i:j].lower()
        i = j
        while i < n and fragment[i].isspace():
            i += 1
        if i >= n or fragment[i] != "=":
            break
        i += 1
        while i < n and fragment[i].isspace():
            i += 1
        if i < n and fragment[i] == '"':
            i += 1
            chars: list[str] = []
            while i < n:
                ch = fragment[i]
                if ch == "\\" and i + 1 < n:
                    chars.append(fragment[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                chars.append(ch)
                i += 1
            value = "".join(chars)
        else:
            k = i
            while k < n and not fragment[k].isspace() and fragment[k] != ",":
                k += 1
            value = fragment[i:k]
            i = k
        out[key] = value
    return out


def _load_client_config_from_key_ref(key_ref_raw: str) -> ClientConfig:
    try:
        payload = _read_key_ref(key_ref_raw)
    except KeyRefNotFoundError:
        LOGGER.info("auth.client using default public client id (key ref missing)")
        return _default_client_config()

    if not isinstance(payload, dict):
        # KEY_REF typically stores an access token; ignore and use the default public client.
        LOGGER.info(
            "auth.client using default public client id (no client config in key ref)"
        )
        return _default_client_config()

    client_id = _as_optional_str(payload.get("client_id"))
    if not client_id:
        LOGGER.info("auth.client using default public client id (client_id missing)")
        return _default_client_config()

    scope_value = payload.get("scope", payload.get("scopes"))
    scope: str | None = None
    if isinstance(scope_value, list):
        parts = [str(x).strip() for x in scope_value if str(x).strip()]
        scope = " ".join(parts) if parts else None
    elif isinstance(scope_value, str):
        scope = scope_value.strip() or None

    return ClientConfig(
        client_id=client_id,
        client_secret=_as_optional_str(payload.get("client_secret")),
        scope=scope,
        audience=_as_optional_str(payload.get("audience")),
        resource=_as_optional_str(payload.get("resource")),
    )


def _default_client_config() -> ClientConfig:
    return ClientConfig(
        client_id=DEFAULT_PUBLIC_CLIENT_ID,
        client_secret=None,
        scope=None,
        audience=None,
        resource=None,
    )


def _require_state_file_for_pending(path: str | None) -> str:
    if not path:
        raise ValueError("internal error: missing auth state file for pending result")
    return path


def _print_wait_instructions(device_flow: dict[str, Any]) -> None:
    url = _as_optional_str(
        device_flow.get("verification_uri_complete")
    ) or _as_optional_str(device_flow.get("verification_uri"))
    code = _as_optional_str(device_flow.get("user_code"))
    if not url and not code:
        return

    # Human-only guidance on stderr; stdout remains JSON result.
    if url:
        print(f"Open: {url}", file=sys.stderr)
    if code:
        print(f"Code: {code}", file=sys.stderr)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def _as_int(value: Any) -> int | None:
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


def _require_state_str(state: dict[str, Any], key: str) -> str:
    value = _as_optional_str(state.get(key))
    if not value:
        raise ValueError(f"invalid auth state file: missing {key}")
    return value


def _require_state_like(source: dict[str, Any], key: str) -> str:
    value = _as_optional_str(source.get(key))
    if not value:
        raise ValueError(f"internal error: missing {key}")
    return value


def _now_epoch() -> int:
    return int(time.time())


def _iso_utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat().replace("+00:00", "Z")
