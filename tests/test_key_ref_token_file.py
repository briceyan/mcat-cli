from __future__ import annotations

import unittest

from mcat_cli.util.key_ref import extract_access_token, parse_json_token_file


class KeyRefTokenFileTest(unittest.TestCase):
    def test_parse_json_token_file(self) -> None:
        token_file = parse_json_token_file(
            {
                "access_token": "abc",
                "refresh_token": "r1",
                "token_type": "Bearer",
                "scope": "mcp:connect",
                "expires_in": "60",
                "expires_at": "2026-01-01T00:00:00Z",
            }
        )
        assert token_file is not None
        self.assertEqual(token_file.access_token, "abc")
        self.assertEqual(token_file.refresh_token, "r1")
        self.assertEqual(token_file.expires_in, 60)

    def test_parse_json_token_file_non_dict(self) -> None:
        self.assertIsNone(parse_json_token_file("abc"))

    def test_extract_access_token_prefers_access_token(self) -> None:
        self.assertEqual(
            extract_access_token({"access_token": "abc", "token": "fallback"}),
            "abc",
        )

    def test_extract_access_token_fallback_token(self) -> None:
        self.assertEqual(extract_access_token({"token": "fallback"}), "fallback")


if __name__ == "__main__":
    unittest.main()
