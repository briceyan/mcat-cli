from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.connection_file import (
    CURRENT_CONNECTION_VERSION,
    read_connection_file,
    write_connection_file,
)


class ConnectionFileTest(unittest.TestCase):
    def test_roundtrip_http_connection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "conn.json"
            write_connection_file(
                str(path),
                {
                    "version": CURRENT_CONNECTION_VERSION,
                    "kind": "http",
                    "endpoint": "https://example.com/mcp",
                    "key_ref": "json://token.json",
                    "flow": "device_code",
                    "state": {"status": "pending"},
                },
            )
            doc = read_connection_file(str(path))
            self.assertEqual(doc["kind"], "http")
            self.assertEqual(doc["endpoint"], "https://example.com/mcp")
            self.assertEqual(doc["key_ref"], "json://token.json")

    def test_legacy_auth_state_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "legacy-auth.json"
            path.write_text(
                """
                {
                  version: 1,
                  endpoint: "https://example.com/mcp",
                  flow: "authorization_code",
                  state: {
                    status: "pending",
                    input_key_ref: "json://token.json"
                  }
                }
                """,
                encoding="utf-8",
            )
            doc = read_connection_file(str(path))
            self.assertEqual(doc["kind"], "http")
            self.assertEqual(doc["flow"], "authorization_code")
            self.assertEqual(doc["key_ref"], "json://token.json")


if __name__ == "__main__":
    unittest.main()
