from __future__ import annotations

import json
import logging
import os
import queue
import secrets
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import UnixStreamServer
from typing import Any

import json5

from .util.atomic_files import write_json_object_locked
from .util.common import normalize_mcp_endpoint, unix_socket_path_from_endpoint

LOGGER = logging.getLogger("mcat.proxy")

_START_TIMEOUT_SECONDS = 5.0
_STOP_TIMEOUT_SECONDS = 5.0
_IO_TIMEOUT_SECONDS = 20.0
_ACTIVE_PROCESSES: dict[int, subprocess.Popen[Any]] = {}


def proxy_up(*, endpoint: str, command: list[str]) -> dict[str, Any]:
    normalized_endpoint, socket_path, proxy_path = _resolve_paths(endpoint)
    resolved_command = _normalize_command(command)

    _cleanup_stale_files(socket_path=socket_path, proxy_path=proxy_path)

    if Path(proxy_path).exists():
        info = _read_proxy_info(proxy_path)
        pid = _extract_pid(info)
        if pid and _is_pid_running(pid):
            raise ValueError(
                f"proxy already running for {normalized_endpoint} (pid={pid})"
            )
        _safe_unlink(proxy_path)

    if Path(socket_path).exists():
        raise ValueError(f"socket path already exists: {socket_path}")

    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from mcat_cli.main import main; main()",
            "proxy",
            "_serve",
            normalized_endpoint,
            "--",
            *resolved_command,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    if not _wait_for_socket(socket_path, process, timeout_seconds=_START_TIMEOUT_SECONDS):
        _terminate_subprocess(process)
        _ACTIVE_PROCESSES.pop(process.pid, None)
        error_detail = ""
        if process.stderr is not None:
            error_detail = process.stderr.read().strip()
        suffix = f": {error_detail[:300]}" if error_detail else ""
        raise ValueError(
            f"proxy failed to start for {normalized_endpoint} (pid={process.pid}){suffix}"
        )

    payload = {
        "version": 1,
        "socket": socket_path,
        "pid": process.pid,
        "command": resolved_command[0],
        "args": resolved_command[1:],
        "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": secrets.token_urlsafe(12),
    }
    try:
        write_json_object_locked(
            proxy_path,
            payload,
            busy_message=f"proxy file is busy: {proxy_path}",
        )
    except Exception:
        _terminate_subprocess(process)
        _safe_unlink(socket_path)
        _ACTIVE_PROCESSES.pop(process.pid, None)
        raise

    if process.stderr is not None:
        process.stderr.close()
    _ACTIVE_PROCESSES[process.pid] = process
    LOGGER.info(
        "proxy.up started endpoint=%s socket=%s pid=%s",
        normalized_endpoint,
        socket_path,
        process.pid,
    )
    return {
        "endpoint": normalized_endpoint,
        "socket": socket_path,
        "proxy": proxy_path,
        "pid": process.pid,
    }


def proxy_down(*, endpoint: str) -> dict[str, Any]:
    normalized_endpoint, socket_path, proxy_path = _resolve_paths(endpoint)
    info = _read_proxy_info_if_exists(proxy_path)

    pid = _extract_pid(info) if info else None
    managed_process = _ACTIVE_PROCESSES.pop(pid, None) if pid else None
    stopped = False
    if pid and _is_pid_running(pid):
        _terminate_pid(pid, timeout_seconds=_STOP_TIMEOUT_SECONDS)
        stopped = True
    if managed_process is not None:
        try:
            managed_process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass

    _safe_unlink(socket_path)
    _safe_unlink(proxy_path)
    _safe_unlink(f"{proxy_path}.lock")
    LOGGER.info(
        "proxy.down endpoint=%s socket=%s stopped=%s",
        normalized_endpoint,
        socket_path,
        stopped,
    )
    return {
        "endpoint": normalized_endpoint,
        "socket": socket_path,
        "proxy": proxy_path,
        "stopped": stopped,
    }


def proxy_status(*, endpoint: str) -> dict[str, Any]:
    normalized_endpoint, socket_path, proxy_path = _resolve_paths(endpoint)
    info = _read_proxy_info_if_exists(proxy_path)
    pid = _extract_pid(info) if info else None
    running = bool(pid and _is_pid_running(pid))

    result: dict[str, Any] = {
        "endpoint": normalized_endpoint,
        "socket": socket_path,
        "proxy": proxy_path,
        "running": running,
        "socket_exists": Path(socket_path).exists(),
        "proxy_exists": Path(proxy_path).exists(),
    }
    if pid:
        result["pid"] = pid
    if info is not None:
        started_at = info.get("started_at")
        if isinstance(started_at, str) and started_at.strip():
            result["started_at"] = started_at
    return result


def run_proxy_server(*, endpoint: str, command: list[str]) -> None:
    normalized_endpoint, socket_path, _ = _resolve_paths(endpoint)
    resolved_command = _normalize_command(command)
    LOGGER.info("proxy.serve start endpoint=%s socket=%s", normalized_endpoint, socket_path)

    bridge = _StdioBridge(resolved_command)
    server = _UnixJsonRpcServer(socket_path=socket_path, bridge=bridge)

    stop_event = threading.Event()

    def _request_shutdown(_: int, __: Any) -> None:
        if stop_event.is_set():
            return
        stop_event.set()
        server.shutdown()

    previous_handlers: dict[int, Any] = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, _request_shutdown)

    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        server.server_close()
        bridge.close()
        _safe_unlink(socket_path)
        LOGGER.info("proxy.serve stopped endpoint=%s socket=%s", normalized_endpoint, socket_path)


class _UnixJsonRpcServer(UnixStreamServer):
    allow_reuse_address = True

    def __init__(self, *, socket_path: str, bridge: "_StdioBridge") -> None:
        self.socket_path = socket_path
        self.bridge = bridge
        super().__init__(socket_path, _UnixJsonRpcHandler)

    def server_bind(self) -> None:
        _safe_unlink(self.socket_path)
        super().server_bind()
        os.chmod(self.socket_path, 0o600)


class _UnixJsonRpcHandler(BaseHTTPRequestHandler):
    server: _UnixJsonRpcServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        LOGGER.debug("proxy.http " + format, *args)

    def do_POST(self) -> None:  # noqa: N802
        length_header = self.headers.get("Content-Length")
        if not length_header or not length_header.isdigit():
            self._send_json(411, {"error": "missing or invalid Content-Length"})
            return

        length = int(length_header)
        body_bytes = self.rfile.read(length)
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON request body"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "JSON-RPC payload must be an object"})
            return

        try:
            response = self.server.bridge.forward(payload)
        except ValueError as exc:
            self._send_json(502, {"error": str(exc)})
            return

        if response is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send_json(200, response)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)


class _StdioBridge:
    def __init__(self, command: list[str]) -> None:
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if self._process.stdin is None or self._process.stdout is None:
            raise ValueError("failed to start stdio bridge process")
        self._stdin = self._process.stdin
        self._stdout = self._process.stdout
        self._stderr = self._process.stderr

        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[str, queue.Queue[dict[str, Any] | Exception]] = {}

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._stderr_reader = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_reader.start()

    def forward(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        request_id = payload.get("id")
        queue_key: str | None = None
        waiter: queue.Queue[dict[str, Any] | Exception] | None = None

        if request_id is not None:
            queue_key = _request_id_key(request_id)
            waiter = queue.Queue(maxsize=1)
            with self._pending_lock:
                self._pending[queue_key] = waiter

        try:
            self._write_message(payload)
            if waiter is None:
                return None

            try:
                item = waiter.get(timeout=_IO_TIMEOUT_SECONDS)
            except queue.Empty:
                raise ValueError("timed out waiting for response from stdio MCP server")
            if isinstance(item, Exception):
                raise ValueError(str(item))
            return item
        finally:
            if queue_key is not None:
                with self._pending_lock:
                    self._pending.pop(queue_key, None)

    def close(self) -> None:
        try:
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=2.0)
        finally:
            try:
                self._stdin.close()
            except OSError:
                pass
            try:
                self._stdout.close()
            except OSError:
                pass
            if self._stderr is not None:
                try:
                    self._stderr.close()
                except OSError:
                    pass

    def _write_message(self, payload: dict[str, Any]) -> None:
        line = (json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
        try:
            with self._write_lock:
                self._stdin.write(line)
                self._stdin.flush()
        except OSError as exc:
            raise ValueError(f"failed to write to stdio MCP server: {exc}") from None

    def _read_loop(self) -> None:
        close_error: Exception | None = None
        try:
            while True:
                message = _read_stdio_message(self._stdout)
                if message is None:
                    break
                response_id = message.get("id")
                if response_id is None:
                    continue
                queue_key = _request_id_key(response_id)
                with self._pending_lock:
                    waiter = self._pending.get(queue_key)
                if waiter is None:
                    continue
                waiter.put(message)
        except Exception as exc:  # pragma: no cover - defensive
            close_error = exc

        if close_error is None:
            close_error = RuntimeError("stdio MCP server closed")
        with self._pending_lock:
            waiters = list(self._pending.values())
        for waiter in waiters:
            waiter.put(close_error)

    def _drain_stderr(self) -> None:
        if self._stderr is None:
            return
        while True:
            line = self._stderr.readline()
            if not line:
                return
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                LOGGER.debug("proxy.stdio stderr=%s", text)


def _read_stdio_message(stream: Any) -> dict[str, Any] | None:
    first_line: bytes | None = None
    while True:
        line = stream.readline()
        if line == b"":
            return None
        if line in {b"\r\n", b"\n"}:
            continue
        first_line = line
        break

    if first_line is None:
        return None

    # Support legacy Content-Length framing in addition to line-delimited JSON.
    if first_line.lower().startswith(b"content-length:"):
        headers: dict[str, str] = {}
        header_line = first_line
        while True:
            text = header_line.decode("ascii", errors="replace")
            if ":" in text:
                key, value = text.split(":", 1)
                headers[key.strip().lower()] = value.strip()
            header_line = stream.readline()
            if header_line == b"":
                return None
            if header_line in {b"\r\n", b"\n"}:
                break

        length_text = headers.get("content-length")
        if not length_text or not length_text.isdigit():
            raise ValueError("invalid stdio frame: missing Content-Length")
        length = int(length_text)
        if length < 0:
            raise ValueError("invalid stdio frame: negative Content-Length")
        body = stream.read(length)
        if len(body) < length:
            return None
    else:
        body = first_line.strip()

    try:
        parsed = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON from stdio MCP server: {exc}") from None
    if not isinstance(parsed, dict):
        raise ValueError("invalid stdio MCP payload: expected JSON object")
    return parsed


def _request_id_key(value: Any) -> str:
    if isinstance(value, (str, int)):
        return str(value)
    raise ValueError("unsupported JSON-RPC request id type")


def _resolve_paths(endpoint: str) -> tuple[str, str, str]:
    transport, normalized_endpoint = normalize_mcp_endpoint(endpoint, field="ENDPOINT")
    if transport != "unix":
        raise ValueError("ENDPOINT must use unix:/// for proxy commands")
    socket_path = unix_socket_path_from_endpoint(normalized_endpoint, field="ENDPOINT")
    proxy_path = f"{socket_path}.json"
    return normalized_endpoint, socket_path, proxy_path


def _normalize_command(command: list[str]) -> list[str]:
    args = list(command)
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        raise ValueError("missing proxy command after --")
    return args


def _cleanup_stale_files(*, socket_path: str, proxy_path: str) -> None:
    info = _read_proxy_info_if_exists(proxy_path)
    pid = _extract_pid(info) if info else None
    if pid and _is_pid_running(pid):
        return
    if pid:
        _safe_unlink(proxy_path)
    if Path(socket_path).exists():
        _safe_unlink(socket_path)


def _read_proxy_info(path: str) -> dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"proxy file not found: {path}") from None
    except OSError as exc:
        raise ValueError(f"unable to read proxy file {path}: {exc}") from None
    try:
        parsed = json5.loads(raw)
    except Exception as exc:
        raise ValueError(f"invalid proxy JSON/JSON5 in {path}: {exc}") from None
    if not isinstance(parsed, dict):
        raise ValueError(f"invalid proxy file {path}: expected JSON object")
    return parsed


def _read_proxy_info_if_exists(path: str) -> dict[str, Any] | None:
    if not Path(path).exists():
        return None
    return _read_proxy_info(path)


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


def _wait_for_socket(
    socket_path: str,
    process: subprocess.Popen[Any],
    *,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if Path(socket_path).exists():
            return True
        if process.poll() is not None:
            return False
        time.sleep(0.05)
    return False


def _safe_unlink(path: str) -> None:
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass
