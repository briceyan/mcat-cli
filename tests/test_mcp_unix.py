from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import UnixStreamServer
from typing import Any

from mcat_cli import mcp
from mcat_cli.util.session_info import read_session_info


class _FakeMcpUnixHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        payload = json.loads(body.decode("utf-8"))
        method = payload.get("method")

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                },
            }
            self._send_json(200, response)
            return

        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {"tools": []},
            }
            self._send_json(200, response)
            return

        self._send_json(
            400,
            {
                "error": f"unsupported method: {method}",
            },
        )

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class _FakeMcpUnixServer(UnixStreamServer):
    allow_reuse_address = True


class McpUnixTransportTest(unittest.TestCase):
    def test_init_and_list_tools_over_unix_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            socket_path = str(Path(temp_dir) / "proxy.sock")
            endpoint = f"unix://{socket_path}"
            session_path = str(Path(temp_dir) / "session.json")

            server = _FakeMcpUnixServer(socket_path, _FakeMcpUnixHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                init_result = mcp.init_session(
                    endpoint=endpoint,
                    key_ref=None,
                    sess_info_file=session_path,
                )
                self.assertEqual(init_result["transport"], "unix")
                self.assertEqual(init_result["session_mode"], "stateless")
                self.assertEqual(init_result["proxy"], f"{socket_path}.json")

                session_doc = read_session_info(session_path)
                self.assertEqual(session_doc["transport"], "unix")
                self.assertIsNone(session_doc.get("key_ref"))
                self.assertEqual(session_doc.get("proxy"), f"{socket_path}.json")

                tools = mcp.list_tools(sess_info_file=session_path)
                self.assertEqual(tools["tools"], [])
            finally:
                server.shutdown()
                server.server_close()

    def test_recv_http_response_reads_content_length_without_waiting_for_close(self) -> None:
        client, server = socket.socketpair()
        try:
            client.settimeout(1.0)

            def writer() -> None:
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: keep-alive\r\n"
                    b"\r\n"
                    b"{}"
                )
                server.sendall(response)
                # Keep socket open briefly to simulate keep-alive behavior.
                time.sleep(0.3)

            thread = threading.Thread(target=writer)
            thread.start()
            status, headers, body = mcp._recv_http_response(client)
            thread.join()

            self.assertEqual(status, 200)
            self.assertEqual(headers.get("content-length"), "2")
            self.assertEqual(body, b"{}")
        finally:
            client.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
