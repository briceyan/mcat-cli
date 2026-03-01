from __future__ import annotations

import hashlib
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import parse as urlparse

import json5
from fastmcp.client.transports.stdio import StdioTransport
from fastmcp.server.providers.proxy import FastMCPProxy, StatefulProxyClient

from .util.atomic_files import write_json_object_locked

_START_TIMEOUT_SECONDS = 8.0
_STOP_TIMEOUT_SECONDS = 5.0
_DEFAULT_PROXY_HOST = "127.0.0.1"
_DEFAULT_PROXY_PATH = "/mcp"
DEFAULT_PROXY_PORT = 6010
_ACTIVE_PROCESSES: dict[int, subprocess.Popen[Any]] = {}


def proxy_up(*, port: int, command: list[str]) -> dict[str, Any]:
    normalized, host, resolved_port, path = _proxy_endpoint_for_port(port)
    resolved_command = _normalize_command(command)
    info_path, log_path = _proxy_artifact_paths(normalized)

    _cleanup_stale_info(info_path)
    existing = _read_proxy_info_if_exists(info_path)
    existing_pid = _extract_pid(existing)
    if existing_pid and _is_pid_running(existing_pid):
        raise ValueError(f"proxy already running for {normalized} (pid={existing_pid})")
    if existing is not None:
        _safe_unlink(info_path)

    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    with Path(log_path).open("ab") as log_file:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "from mcat_cli.main import main; main()",
                "proxy",
                "_serve",
                normalized,
                "--",
                *resolved_command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
        )

    if not _wait_for_http_ready(
        host, resolved_port, process, timeout_seconds=_START_TIMEOUT_SECONDS
    ):
        _terminate_subprocess(process)
        _ACTIVE_PROCESSES.pop(process.pid, None)
        raise ValueError(
            f"proxy failed to start for {normalized} (pid={process.pid}); see log: {log_path}"
        )

    payload = {
        "version": 1,
        "endpoint": normalized,
        "host": host,
        "port": resolved_port,
        "path": path,
        "pid": process.pid,
        "command": resolved_command[0],
        "args": resolved_command[1:],
        "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": secrets.token_urlsafe(12),
        "log_file": str(log_path),
    }
    write_json_object_locked(
        info_path,
        payload,
        busy_message=f"proxy file is busy: {info_path}",
    )
    _ACTIVE_PROCESSES[process.pid] = process
    return {
        "endpoint": normalized,
        "proxy": str(info_path),
        "pid": process.pid,
        "log_file": str(log_path),
    }


def proxy_down(*, port: int) -> dict[str, Any]:
    normalized, _, _, _ = _proxy_endpoint_for_port(port)
    info_path, log_path = _proxy_artifact_paths(normalized)
    info = _read_proxy_info_if_exists(info_path)

    pid = _extract_pid(info)
    managed = _ACTIVE_PROCESSES.pop(pid, None) if pid else None
    stopped = False
    if pid and _is_pid_running(pid):
        _terminate_pid(pid, timeout_seconds=_STOP_TIMEOUT_SECONDS)
        stopped = True
    if managed is not None:
        try:
            managed.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass

    _safe_unlink(info_path)
    _safe_unlink(f"{info_path}.lock")
    return {
        "endpoint": normalized,
        "proxy": str(info_path),
        "stopped": stopped,
        "log_file": str(log_path),
    }


def proxy_status(*, port: int) -> dict[str, Any]:
    normalized, _, _, _ = _proxy_endpoint_for_port(port)
    info_path, log_path = _proxy_artifact_paths(normalized)
    info = _read_proxy_info_if_exists(info_path)
    pid = _extract_pid(info)
    running = bool(pid and _is_pid_running(pid))

    result: dict[str, Any] = {
        "endpoint": normalized,
        "proxy": str(info_path),
        "log_file": str(log_path),
        "running": running,
        "proxy_exists": Path(info_path).exists(),
    }
    if pid:
        result["pid"] = pid
    return result


def run_proxy_server(*, endpoint: str, command: list[str]) -> None:
    normalized, host, port, path = _parse_proxy_endpoint(endpoint)
    resolved_command = _normalize_command(command)
    transport = StdioTransport(
        command=resolved_command[0],
        args=resolved_command[1:],
        keep_alive=True,
    )
    # Reuse one upstream stdio client across requests so the subprocess session
    # is initialized once and stays stable for subsequent tool resolution/calls.
    shared_client = StatefulProxyClient(transport=transport)
    proxy = FastMCPProxy(
        client_factory=lambda: shared_client,
        name="mcat-fastmcp-proxy",
    )
    proxy.run(
        transport="http",
        host=host,
        port=port,
        path=path,
        show_banner=False,
    )
    _ = normalized


def _proxy_endpoint_for_port(port: int) -> tuple[str, str, int, str]:
    resolved_port = _normalize_port(port)
    endpoint = (
        f"http://{_DEFAULT_PROXY_HOST}:{resolved_port}{_DEFAULT_PROXY_PATH}"
    )
    normalized, host, parsed_port, path = _parse_proxy_endpoint(endpoint)
    return normalized, host, parsed_port, path


def _normalize_port(value: int) -> int:
    port = int(value)
    if port <= 0 or port > 65535:
        raise ValueError("PORT must be in range 1..65535")
    return port


def _parse_proxy_endpoint(raw: str) -> tuple[str, str, int, str]:
    text = raw.strip()
    parsed = urlparse.urlsplit(text)
    scheme = parsed.scheme.lower()
    if scheme != "http":
        raise ValueError("ENDPOINT must be an http:// URL for proxy commands")
    if not parsed.hostname:
        raise ValueError("ENDPOINT must include a host")
    if parsed.port is None:
        raise ValueError("ENDPOINT must include an explicit port")
    if parsed.query or parsed.fragment:
        raise ValueError("ENDPOINT must not include query or fragment")

    host = parsed.hostname
    port = int(parsed.port)
    if port <= 0 or port > 65535:
        raise ValueError("ENDPOINT port is out of range")
    path = parsed.path or "/mcp"
    if not path.startswith("/"):
        path = "/" + path

    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    normalized = urlparse.urlunsplit((scheme, f"{host_part}:{port}", path, "", ""))
    return normalized, host, port, path


def _normalize_command(command: list[str]) -> list[str]:
    args = list(command)
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        raise ValueError("missing proxy command after --")
    return args


def _proxy_artifact_paths(endpoint: str) -> tuple[Path, Path]:
    digest = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:16]
    tempdir = Path(tempfile.gettempdir())
    info = tempdir / f"mcat.proxy.{digest}.json"
    log = tempdir / f"mcat.proxy.{digest}.log"
    return info, log


def _cleanup_stale_info(path: Path) -> None:
    info = _read_proxy_info_if_exists(path)
    pid = _extract_pid(info)
    if pid and _is_pid_running(pid):
        return
    _safe_unlink(path)
    _safe_unlink(f"{path}.lock")


def _wait_for_http_ready(
    host: str,
    port: int,
    process: subprocess.Popen[Any],
    *,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    probe_host = _probe_host_for_connect(host)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection((probe_host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _probe_host_for_connect(host: str) -> str:
    if host == "0.0.0.0":
        return "127.0.0.1"
    if host == "::":
        return "::1"
    return host


def _read_proxy_info_if_exists(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"unable to read proxy file {path}: {exc}") from None
    try:
        parsed = json5.loads(raw)
    except Exception as exc:
        raise ValueError(f"invalid proxy JSON/JSON5 in {path}: {exc}") from None
    if not isinstance(parsed, dict):
        raise ValueError(f"invalid proxy file {path}: expected JSON object")
    return parsed


def _extract_pid(info: dict[str, Any] | None) -> int | None:
    if not info:
        return None
    pid = info.get("pid")
    if isinstance(pid, int) and pid > 0:
        return pid
    if isinstance(pid, str) and pid.isdigit():
        return int(pid)
    return None


def _is_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_pid(pid: int, *, timeout_seconds: float) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _is_pid_running(pid):
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _terminate_subprocess(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1.0)


def _safe_unlink(path: str | Path) -> None:
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return
