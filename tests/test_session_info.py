from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.session_info import (
    SessionInfo,
    read_session_info,
    read_session_info_model,
    write_session_info_model,
)


class SessionInfoTest(unittest.TestCase):
    def test_session_info_roundtrip(self) -> None:
        model = SessionInfo(
            version=1,
            endpoint="https://example.com/mcp",
            key_ref="json://token.json",
            session_id="abc",
            session_mode="stateful",
            protocol_version="2025-03-26",
            server_capabilities={"tools": {}},
        )
        self.assertEqual(SessionInfo.from_doc(model.to_doc()), model)

    def test_session_info_validate_missing_endpoint(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid session info file: missing endpoint"):
            SessionInfo.from_doc({"version": 1, "key_ref": "json://token.json"})

    def test_write_then_read_session_info(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            write_session_info_model(
                str(path),
                SessionInfo(
                    version=1,
                    endpoint="https://example.com/mcp",
                    key_ref="json://token.json",
                    session_mode="stateless",
                ),
            )

            read_back = read_session_info_model(str(path))
            self.assertEqual(read_back.endpoint, "https://example.com/mcp")
            self.assertEqual(read_back.session_mode, "stateless")
            self.assertEqual(read_session_info(str(path))["key_ref"], "json://token.json")


if __name__ == "__main__":
    unittest.main()
