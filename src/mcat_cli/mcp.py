from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from .util.files import locked_file, write_text_atomic

LOGGER = logging.getLogger("mcat.mcp")


def init_session(*, endpoint: str, key_ref: str, sess_info_file: str) -> dict[str, Any]:
    LOGGER.info("mcp.init requested endpoint=%s", endpoint)
    normalized_endpoint = _normalize_url(endpoint, field="ENDPOINT")
    normalized_key_ref = _normalize_key_ref(key_ref)
    if not sess_info_file.strip():
        raise ValueError("SESS_INFO_FILE is required")

    token = _resolve_access_token_from_key_ref(normalized_key_ref)
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "mcat-cli", "version": "0.1.0"},
        },
    }
    init_resp = _post_jsonrpc(normalized_endpoint, token, init_payload)
    _raise_jsonrpc_error(init_resp["messages"])
    session_id = _as_optional_str(init_resp["headers"].get("mcp-session-id"))

    initialized_payload = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    initialized_resp = _post_jsonrpc(
        normalized_endpoint,
        token,
        initialized_payload,
        session_id=session_id,
    )
    _raise_jsonrpc_error(initialized_resp["messages"])
    session_id = _as_optional_str(
        initialized_resp["headers"].get("mcp-session-id")
    ) or session_id
    if not session_id:
        raise ValueError(
            "initialize succeeded but server did not return mcp-session-id"
        )

    session_doc = {
        "version": 1,
        "session_id": session_id,
        "key_ref": normalized_key_ref,
        "endpoint": normalized_endpoint,
    }
    _write_session_doc(sess_info_file, session_doc)
    return {
        "session_id": session_doc["session_id"],
        "session_file": str(Path(sess_info_file)),
    }


def list_tools(*, sess_info_file: str) -> dict[str, Any]:
    LOGGER.info("mcp.tool.list requested sess_info_file=%s", sess_info_file)
    session_doc = _read_session_doc(sess_info_file)
    endpoint = _normalize_url(
        _require_str(session_doc.get("endpoint"), "endpoint"), field="endpoint"
    )
    key_ref = _normalize_key_ref(_require_str(session_doc.get("key_ref"), "key_ref"))
    token = _resolve_access_token_from_key_ref(key_ref)
    existing_session_id = _as_optional_str(session_doc.get("session_id"))
    if not existing_session_id:
        raise ValueError("session info file is missing session_id; run `mcat init`")

    list_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    list_resp = _post_jsonrpc(
        endpoint,
        token,
        list_payload,
        session_id=existing_session_id,
    )
    _raise_jsonrpc_error(list_resp["messages"])
    active_session_id = _as_optional_str(
        list_resp["headers"].get("mcp-session-id")
    ) or existing_session_id

    if active_session_id and active_session_id != existing_session_id:
        session_doc["session_id"] = active_session_id
        _write_session_doc(sess_info_file, session_doc)

    tools = _extract_tools(list_resp["messages"])
    result: dict[str, Any]
    if tools is not None:
        result = {"tools": tools}
    else:
        result = {"messages": list_resp["messages"]}
    if active_session_id:
        result["session_id"] = active_session_id
    return result


def call_tool(
    *, tool_name: str, args_input: str, sess_info_file: str
) -> dict[str, Any]:
    LOGGER.info("mcp.tool.call requested tool_name=%s", tool_name)
    name = tool_name.strip()
    if not name:
        raise ValueError("TOOL_NAME is required")
    arguments = _parse_tool_arguments(args_input)

    session_doc = _read_session_doc(sess_info_file)
    endpoint = _normalize_url(
        _require_str(session_doc.get("endpoint"), "endpoint"), field="endpoint"
    )
    key_ref = _normalize_key_ref(_require_str(session_doc.get("key_ref"), "key_ref"))
    token = _resolve_access_token_from_key_ref(key_ref)
    existing_session_id = _as_optional_str(session_doc.get("session_id"))
    if not existing_session_id:
        raise ValueError("session info file is missing session_id; run `mcat init`")

    call_payload = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        },
    }
    call_resp = _post_jsonrpc(
        endpoint,
        token,
        call_payload,
        session_id=existing_session_id,
    )
    _raise_jsonrpc_error(call_resp["messages"])
    active_session_id = _as_optional_str(
        call_resp["headers"].get("mcp-session-id")
    ) or existing_session_id

    if active_session_id and active_session_id != existing_session_id:
        session_doc["session_id"] = active_session_id
        _write_session_doc(sess_info_file, session_doc)

    raw_result = _extract_first_result(call_resp["messages"])
    if raw_result is None:
        return {"messages": call_resp["messages"]}
    if isinstance(raw_result, dict):
        return raw_result
    return {"value": raw_result}


def _parse_tool_arguments(args_input: str) -> dict[str, Any]:
    spec = args_input.strip()
    if not spec:
        raise ValueError("ARGS is required")

    source = "ARGS"
    if spec == "@-":
        source = "stdin"
        text = sys.stdin.read()
    elif spec.startswith("@"):
        path = spec[1:].strip()
        if not path:
            raise ValueError("invalid ARGS reference: missing file path after @")
        source = path
        file_path = Path(path)
        try:
            text = file_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise ValueError(f"ARGS file not found: {path}") from None
        except OSError as exc:
            raise ValueError(f"unable to read ARGS file {path}: {exc}") from None
    else:
        text = args_input

    parsed = _parse_json_or_json5(text, source=source)
    if not isinstance(parsed, dict):
        raise ValueError("ARGS must be a JSON object")
    return parsed


def _parse_json_or_json5(text: str, *, source: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as json_exc:
        json_msg = json_exc.msg

    try:
        import json5
    except ImportError:
        raise ValueError(
            f"invalid JSON in {source}: {json_msg} (install `json5` for JSON5 input)"
        ) from None

    try:
        return json5.loads(text)
    except Exception as exc:
        raise ValueError(f"invalid JSON/JSON5 in {source}: {exc}") from None


def _extract_first_result(messages: list[dict[str, Any]]) -> Any | None:
    for message in messages:
        if "result" in message:
            return message.get("result")
    return None


def _raise_jsonrpc_error(messages: list[dict[str, Any]]) -> None:
    error_text = _extract_jsonrpc_error_message(messages)
    if error_text:
        raise ValueError(error_text)


def _extract_jsonrpc_error_message(messages: list[dict[str, Any]]) -> str | None:
    for message in messages:
        error_obj = message.get("error")
        if not isinstance(error_obj, dict):
            continue

        message_text = _as_optional_str(error_obj.get("message"))
        code = error_obj.get("code")
        data = error_obj.get("data")

        parts: list[str] = []
        if message_text:
            parts.append(message_text)
        if code is not None:
            parts.append(f"code={code}")
        if data is not None:
            try:
                serialized = json.dumps(data, ensure_ascii=False)
            except TypeError:
                serialized = str(data)
            if serialized:
                parts.append(f"data={serialized}")

        if parts:
            return "jsonrpc error: " + "; ".join(parts)
        return "jsonrpc error"
    return None


def _read_session_doc(path: str) -> dict[str, Any]:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"session info file not found: {path}") from None
    except OSError as exc:
        raise ValueError(f"unable to read session info file: {exc}") from None

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid session info JSON: {exc.msg}") from None

    if not isinstance(doc, dict):
        raise ValueError("invalid session info file: expected JSON object")
    return doc


def _write_session_doc(path: str, session_doc: dict[str, Any]) -> None:
    serialized = json.dumps(
        session_doc,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    ) + "\n"
    lock_path = f"{path}.lock"
    try:
        with locked_file(lock_path):
            write_text_atomic(path, serialized)
    except BlockingIOError:
        raise ValueError(f"session info file is busy: {path}") from None


def _post_jsonrpc(
    endpoint: str,
    token: str,
    payload: dict[str, Any],
    *,
    session_id: str | None = None,
) -> dict[str, Any]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "User-Agent": "mcat-cli/0.1",
    }
    if token.strip():
        headers["Authorization"] = f"Bearer {token}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id

    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    method = _as_optional_str(payload.get("method")) or "<unknown>"
    LOGGER.info("mcp.http POST %s method=%s", endpoint, method)

    req = urlrequest.Request(url=endpoint, method="POST", data=data, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=60.0) as resp:
            status = int(getattr(resp, "status", 200))
            body = resp.read().decode("utf-8", errors="replace")
            content_type = resp.headers.get("content-type")
            response_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urlerror.HTTPError as exc:
        status = int(exc.code)
        body = exc.read().decode("utf-8", errors="replace")
        msg = _extract_http_error_message(body)
        LOGGER.info("mcp.http POST %s method=%s -> %s", endpoint, method, status)
        if msg:
            raise ValueError(f"mcp request failed ({status}): {msg}") from None
        raise ValueError(f"mcp request failed ({status})") from None
    except urlerror.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ValueError(f"network error contacting {endpoint}: {reason}") from None

    LOGGER.info("mcp.http POST %s method=%s -> %s", endpoint, method, status)
    messages = _parse_mcp_response(body, content_type)
    return {"headers": response_headers, "messages": messages}


def _parse_mcp_response(text: str, content_type: str | None) -> list[dict[str, Any]]:
    body = text.strip()
    if not body:
        return []

    ct = (content_type or "").lower()
    if "text/event-stream" in ct:
        return _parse_sse(text)
    if "application/json" in ct or "+json" in ct:
        return _parse_json_body(text)

    # Fallback for servers with missing or incorrect content-type.
    try:
        return _parse_json_body(text)
    except ValueError:
        return _parse_sse(text)


def _parse_sse(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data_lines: list[str] = []

    def flush_event() -> None:
        if not data_lines:
            return
        payload = "\n".join(data_lines).strip()
        data_lines.clear()
        if not payload or payload == "[DONE]":
            return
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return
        if isinstance(parsed, dict):
            out.append(parsed)

    for line in text.splitlines():
        if line == "":
            flush_event()
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            payload = line.removeprefix("data:")
            if payload.startswith(" "):
                payload = payload[1:]
            data_lines.append(payload)

    flush_event()
    return out


def _parse_json_body(text: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON response: {exc.msg}") from None

    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        if all(isinstance(item, dict) for item in parsed):
            return parsed
        raise ValueError("JSON response array contains non-object items")
    raise ValueError("JSON response is not an object or array of objects")


def _extract_http_error_message(body: str) -> str | None:
    body = body.strip()
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return body[:200]
    if isinstance(parsed, dict):
        for key in ("error_description", "error", "message"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return body[:200]


def _extract_tools(messages: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    for message in messages:
        result = message.get("result")
        if not isinstance(result, dict):
            continue
        tools = result.get("tools")
        if isinstance(tools, list) and all(isinstance(tool, dict) for tool in tools):
            return tools
    return None


def _resolve_access_token_from_key_ref(key_ref: str) -> str:
    payload = _read_key_ref_value(key_ref)
    token = _extract_access_token(payload)
    if token:
        return token
    raise ValueError("KEY_REF does not contain an access token")


def _read_key_ref_value(key_ref: str) -> Any:
    if key_ref.startswith("env://"):
        var_name = key_ref[len("env://") :].strip()
        value = os.environ.get(var_name)
        if value is None:
            raise ValueError(f"environment variable not set: {var_name}")
        return _maybe_parse_json_scalar(value)

    if key_ref.startswith(".env://"):
        rest = key_ref[len(".env://") :]
        path, var_name = rest.rsplit(":", 1)
        values = _read_dotenv_file(path)
        if var_name not in values:
            raise ValueError(f"variable not found in .env file: {var_name}")
        return _maybe_parse_json_scalar(values[var_name])

    if key_ref.startswith("json://"):
        path = key_ref[len("json://") :].strip()
        p = Path(path)
        if not p.exists():
            raise ValueError(f"json key file not found: {path}")
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in {path}: {exc.msg}") from None

    raise ValueError("invalid KEY_REF")


def _extract_access_token(value: Any) -> str | None:
    if isinstance(value, str):
        token = value.strip()
        return token or None
    if isinstance(value, dict):
        for key in ("access_token", "accessToken", "token"):
            token = value.get(key)
            if isinstance(token, str) and token.strip():
                return token.strip()
    return None


def _read_dotenv_file(path: str) -> dict[str, str]:
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
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        values[key] = _dotenv_unquote(raw_value.strip())
    return values


def _dotenv_unquote(value: str) -> str:
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


def _maybe_parse_json_scalar(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return ""
    if stripped[0] in "{[\"" or stripped in {"true", "false", "null"}:
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return text
    return text


def _require_str(value: Any, field: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ValueError(f"invalid session info file: missing {field}")


def _as_optional_str(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


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
