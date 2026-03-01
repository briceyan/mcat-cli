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
            finally:
                down = proxy.proxy_down(endpoint=endpoint)
                self.assertFalse(Path(up["proxy"]).exists())
                if status.get("running"):
                    self.assertTrue(down["stopped"])


def _stub_server_source() -> str:
    return (
        "import json\\n"
        "import sys\\n"
        "\\n"
        "def emit(payload):\\n"
        "    sys.stdout.write(json.dumps(payload, separators=(\\\",\\\", \\\":\\\")))\\n"
        "    sys.stdout.write('\\\\n')\\n"
        "    sys.stdout.flush()\\n"
        "\\n"
        "for line in sys.stdin:\\n"
        "    line = line.strip()\\n"
        "    if not line:\\n"
        "        continue\\n"
        "    req = json.loads(line)\\n"
        "    method = req.get('method')\\n"
        "    req_id = req.get('id')\\n"
        "    if method == 'initialize':\\n"
        "        emit({'jsonrpc':'2.0','id':req_id,'result':{'protocolVersion':'2025-03-26','capabilities':{'tools':{}}}})\\n"
        "        continue\\n"
        "    if method == 'notifications/initialized':\\n"
        "        continue\\n"
        "    if method == 'tools/list':\\n"
        "        emit({'jsonrpc':'2.0','id':req_id,'result':{'tools':[{'name':'ping','inputSchema':{}}]}})\\n"
        "        continue\\n"
        "    if req_id is not None:\\n"
        "        emit({'jsonrpc':'2.0','id':req_id,'result':{}})\\n"
    )


if __name__ == "__main__":
    unittest.main()
