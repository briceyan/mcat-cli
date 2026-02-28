from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.auth_state import (
    AuthState,
    read_auth_state,
    read_auth_state_file,
    write_auth_state,
)


class AuthStateTest(unittest.TestCase):
    def test_auth_state_from_doc_roundtrip(self) -> None:
        doc = {
            "version": 1,
            "endpoint": "https://example.com/mcp",
            "flow": "device_code",
            "state": {"status": "pending"},
        }
        model = AuthState.from_doc(doc)
        self.assertEqual(model.to_doc(), doc)

    def test_auth_state_validate_missing_flow(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid auth state file: missing flow"):
            AuthState.from_doc(
                {
                    "version": 1,
                    "endpoint": "https://example.com/mcp",
                    "state": {},
                }
            )

    def test_write_then_read_auth_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth-state.json"
            write_auth_state(
                str(path),
                AuthState(
                    version=1,
                    endpoint="https://example.com/mcp",
                    flow="authorization_code",
                    state={"status": "pending", "oauth_state": "abc"},
                ),
            )
            model = read_auth_state(str(path))
            self.assertEqual(model.flow, "authorization_code")
            self.assertEqual(model.state["oauth_state"], "abc")
            self.assertEqual(read_auth_state_file(str(path))["endpoint"], "https://example.com/mcp")


if __name__ == "__main__":
    unittest.main()
