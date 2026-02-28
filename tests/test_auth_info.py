from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.auth_info import (
    AuthInfo,
    auth_info_from_doc,
    auth_info_to_doc,
    read_auth_info_doc,
    write_auth_info,
)


class AuthInfoTest(unittest.TestCase):
    def test_auth_info_from_doc_and_to_doc(self) -> None:
        doc = {
            "version": 1,
            "endpoint": "https://example.com/mcp",
            "flow": "device_code",
            "state": {"status": "pending"},
        }

        info = auth_info_from_doc(doc)
        self.assertEqual(
            info,
            AuthInfo(
                version=1,
                endpoint="https://example.com/mcp",
                flow="device_code",
                state={"status": "pending"},
            ),
        )
        self.assertEqual(auth_info_to_doc(info), doc)

    def test_auth_info_from_doc_missing_flow(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid auth state file: missing flow"):
            auth_info_from_doc(
                {
                    "version": 1,
                    "endpoint": "https://example.com/mcp",
                    "state": {},
                }
            )

    def test_write_then_read_auth_info_doc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.json"
            write_auth_info(
                str(path),
                AuthInfo(
                    version=1,
                    endpoint="https://example.com/mcp",
                    flow="authorization_code",
                    state={"status": "pending", "oauth_state": "abc"},
                ),
            )

            read_back = read_auth_info_doc(str(path))
            self.assertEqual(read_back["version"], 1)
            self.assertEqual(read_back["flow"], "authorization_code")
            self.assertEqual(read_back["state"]["oauth_state"], "abc")


if __name__ == "__main__":
    unittest.main()
