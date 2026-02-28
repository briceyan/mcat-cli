from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.key_ref import (
    WebToken,
    extract_access_token,
    read_web_token,
    write_web_token,
)


class KeyRefWebTokenTest(unittest.TestCase):
    def test_web_token_from_dict(self) -> None:
        token = WebToken.from_value(
            {
                "access_token": "abc",
                "refresh_token": "r1",
                "token_type": "Bearer",
                "scope": "mcp:connect",
                "expires_in": "60",
                "expires_at": "2026-01-01T00:00:00Z",
            }
        )
        self.assertEqual(token.access_token, "abc")
        self.assertEqual(token.refresh_token, "r1")
        self.assertEqual(token.expires_in, 60)

    def test_web_token_from_string(self) -> None:
        token = WebToken.from_value("abc")
        self.assertEqual(token.access_token, "abc")

    def test_extract_access_token(self) -> None:
        self.assertEqual(extract_access_token({"token": "fallback"}), "fallback")

    def test_read_web_token_from_json_key_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            token_file = Path(temp_dir) / "token.json"
            token_file.write_text(
                json.dumps({"access_token": "abc", "token_type": "Bearer"}),
                encoding="utf-8",
            )
            token = read_web_token(f"json://{token_file}")
            self.assertEqual(token.access_token, "abc")

    def test_write_web_token_to_json_key_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            token_file = Path(temp_dir) / "token.json"
            write_web_token(
                f"json://{token_file}",
                WebToken(access_token="abc", token_type="Bearer"),
                overwrite=True,
            )
            saved = json.loads(token_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["access_token"], "abc")
            self.assertEqual(saved["token_type"], "Bearer")


if __name__ == "__main__":
    unittest.main()
