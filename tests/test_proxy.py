from __future__ import annotations

import socket
import sys
import tempfile
import unittest
from pathlib import Path

from mcat_cli import mcp, proxy


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ProxyFastMcpTest(unittest.TestCase):
    def test_proxy_up_requires_command(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing proxy command"):
            proxy.proxy_up(endpoint="http://127.0.0.1:9876/mcp", command=[])

    def test_proxy_up_status_down_with_init(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            port = _free_port()
            endpoint = f"http://127.0.0.1:{port}/mcp"
            sess_file = Path(temp_dir) / "session.json"
            stub_file = Path(temp_dir) / "stub_stdio_server.py"
            stub_file.write_text(
                _stub_server_source(),
                encoding="utf-8",
            )
            try:
                proxy.proxy_down(endpoint=endpoint)
            except Exception:
                pass

            up = proxy.proxy_up(
                endpoint=endpoint,
                command=[sys.executable, str(stub_file)],
            )
            status: dict[str, object] = {}
            try:
                self.assertEqual(up["endpoint"], endpoint)
                self.assertTrue(Path(up["proxy"]).exists())

                status = proxy.proxy_status(endpoint=endpoint)
                self.assertTrue(status["running"])

                init_result = mcp.init_session(
                    endpoint=endpoint,
                    key_ref=None,
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
                down = proxy.proxy_down(endpoint=endpoint)
                self.assertFalse(Path(up["proxy"]).exists())
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
