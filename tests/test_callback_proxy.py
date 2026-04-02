from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlrequest

from mcat_cli import auth as auth_mod


class CallbackProxyTest(unittest.TestCase):
    def test_build_callback_target_returns_auth_listen_and_target_urls(self) -> None:
        result = auth_mod.build_callback_target(
            listen="0.0.0.0:0",
            target_host="host.docker.internal",
        )
        self.assertEqual(result["callback_path"], "/callback")
        self.assertGreater(result["port"], 0)
        self.assertEqual(
            result["listen_url"],
            f"http://0.0.0.0:{result['port']}/callback",
        )
        self.assertEqual(
            result["target_url"],
            f"http://host.docker.internal:{result['port']}/callback",
        )

    def test_callback_proxy_forwards_raw_query_and_response(self) -> None:
        seen: dict[str, str] = {}
        hit = threading.Event()

        class UpstreamHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen["path"] = self.path
                body = b"proxied\n"
                self.send_response(201)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                hit.set()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        upstream_url = (
            f"http://127.0.0.1:{upstream.server_address[1]}/internal/callback?base=1"
        )

        handle = auth_mod.start_callback_proxy(
            listen="http://127.0.0.1:0/external/callback",
            target=upstream_url,
        )
        try:
            req = urlrequest.Request(
                f"{handle.listen_uri}?code=abc&state=xyz",
                method="GET",
            )
            with urlrequest.urlopen(req, timeout=5.0) as resp:
                status = int(getattr(resp, "status", 200))
                content_type = resp.headers.get("Content-Type")
                body = resp.read().decode("utf-8")

            self.assertEqual(status, 201)
            self.assertEqual(content_type, "text/plain; charset=utf-8")
            self.assertEqual(body, "proxied\n")
            self.assertTrue(hit.wait(1.0))
            self.assertEqual(
                seen["path"],
                "/internal/callback?base=1&code=abc&state=xyz",
            )
            self.assertTrue(handle.listen_uri.endswith("/external/callback"))
        finally:
            auth_mod.stop_callback_proxy(handle)
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
