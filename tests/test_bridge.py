from __future__ import annotations

import socket
import sys
import tempfile
import unittest
from pathlib import Path
from urllib import parse as urlparse

import json5

from mcat_cli import bridge, mcp


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class BridgeFastMcpTest(unittest.TestCase):
    def test_bridge_start_requires_command(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing bridge command"):
            bridge.bridge_start(
                connection_file="ignored.connection.json",
                port=9876,
                command=[],
            )

    def test_bridge_start_auto_port_reports_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            conn_file = Path(temp_dir) / "local.connection.json"
            stub_file = Path(temp_dir) / "stub_stdio_server.py"
            stub_file.write_text(
                _stub_server_source(),
                encoding="utf-8",
            )
            up = bridge.bridge_start(
                connection_file=str(conn_file),
                port=None,
                command=[sys.executable, str(stub_file)],
            )
            endpoint = str(up["endpoint"])
            parsed = urlparse.urlsplit(endpoint)
            self.assertEqual(parsed.scheme, "http")
            self.assertEqual(parsed.hostname, "127.0.0.1")
            self.assertEqual(parsed.path, "/mcp")
            self.assertIsNotNone(parsed.port)
            port = int(parsed.port or 0)
            self.assertGreater(port, 0)
            conn_doc = json5.loads(conn_file.read_text(encoding="utf-8"))
            self.assertEqual(conn_doc["endpoint"], endpoint)
            self.assertEqual(conn_doc["kind"], "stdio")
            try:
                status = bridge.bridge_status(connection_file=str(conn_file))
                self.assertTrue(status["running"])
                self.assertTrue(status["bridge_exists"])
            finally:
                bridge.bridge_stop(connection_file=str(conn_file))

    def test_bridge_start_status_stop_with_init(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            port = _free_port()
            endpoint = f"http://127.0.0.1:{port}/mcp"
            conn_file = Path(temp_dir) / "local.connection.json"
            sess_file = Path(temp_dir) / "session.json"
            stub_file = Path(temp_dir) / "stub_stdio_server.py"
            stub_file.write_text(
                _stub_server_source(),
                encoding="utf-8",
            )

            up = bridge.bridge_start(
                connection_file=str(conn_file),
                port=port,
                command=[sys.executable, str(stub_file)],
            )
            status: dict[str, object] = {}
            try:
                self.assertEqual(up["endpoint"], endpoint)

                status = bridge.bridge_status(connection_file=str(conn_file))
                self.assertTrue(status["running"])
                self.assertTrue(status["bridge_exists"])

                init_result = mcp.init_session(
                    connection_file=str(conn_file),
                    sess_info_file=str(sess_file),
                )
                self.assertIn(init_result["session_mode"], {"stateful", "stateless"})

                tools = mcp.list_tools(sess_info_file=str(sess_file))
                self.assertIsInstance(tools.get("tools"), list)
                call = mcp.call_tool(
                    tool_name="ping",
                    arguments={},
                    sess_info_file=str(sess_file),
                )
                self.assertEqual(call.get("content"), [{"type": "text", "text": "pong"}])
                self.assertFalse(call.get("isError", False))
            finally:
                down = bridge.bridge_stop(connection_file=str(conn_file))
                if status.get("running"):
                    self.assertTrue(down["stopped"])


def _stub_server_source() -> str:
    return """import json
import sys

initialized = False


def emit(payload):
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))
    sys.stdout.write("\\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    method = req.get("method")
    req_id = req.get("id")
    if method == "initialize":
        if initialized:
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32600,
                        "message": "initialize called more than once",
                    },
                }
            )
            continue
        initialized = True
        emit(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "stub", "version": "0.0.0"},
                },
            }
        )
        continue
    if method == "notifications/initialized":
        continue
    if method == "tools/list":
        emit(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": [{"name": "ping", "inputSchema": {}}]},
            }
        )
        continue
    if method == "tools/call":
        params = req.get("params") or {}
        if params.get("name") == "ping":
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": "pong"}],
                        "isError": False,
                    },
                }
            )
            continue
        emit(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": "Unknown tool"}],
                    "isError": True,
                },
            }
        )
        continue
    if req_id is not None:
        emit({"jsonrpc": "2.0", "id": req_id, "result": {}})
"""


if __name__ == "__main__":
    unittest.main()
