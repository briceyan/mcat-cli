from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.session_info import (
    SessionInfo,
    read_session_info_doc,
    session_info_from_doc,
    session_info_to_doc,
    write_session_info_model,
)


class SessionInfoTest(unittest.TestCase):
    def test_session_info_from_doc_and_to_doc(self) -> None:
        doc = {
            "version": 1,
            "endpoint": "https://example.com/mcp",
            "key_ref": "json://token.json",
            "session_id": "abc",
            "session_mode": "stateful",
            "protocol_version": "2025-03-26",
            "server_capabilities": {"tools": {}},
            "extra_field": "kept",
        }

        info = session_info_from_doc(doc)
        self.assertEqual(
            info,
            SessionInfo(
                version=1,
                endpoint="https://example.com/mcp",
                key_ref="json://token.json",
                session_id="abc",
                session_mode="stateful",
                protocol_version="2025-03-26",
                server_capabilities={"tools": {}},
                extras={"extra_field": "kept"},
            ),
        )
        self.assertEqual(session_info_to_doc(info), doc)

    def test_session_info_from_doc_missing_endpoint(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid session info file: missing endpoint"):
            session_info_from_doc({"version": 1, "key_ref": "json://token.json"})

    def test_write_then_read_session_info_doc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            write_session_info_model(
                str(path),
                SessionInfo(
                    version=1,
                    endpoint="https://example.com/mcp",
                    key_ref="json://token.json",
                    session_mode="stateless",
                    extras={"custom": 1},
                ),
            )

            read_back = read_session_info_doc(str(path))
            self.assertEqual(read_back["endpoint"], "https://example.com/mcp")
            self.assertEqual(read_back["session_mode"], "stateless")
            self.assertEqual(read_back["custom"], 1)


if __name__ == "__main__":
    unittest.main()
