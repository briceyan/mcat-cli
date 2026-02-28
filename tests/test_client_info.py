from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.client_info import (
    read_client_info_file,
    resolve_client_secret_spec,
)


class ClientInfoFileTest(unittest.TestCase):
    def test_read_client_info_file_empty_ref(self) -> None:
        info = read_client_info_file(None)
        self.assertIsNone(info.client_id)
        self.assertIsNone(info.client_secret_spec)
        self.assertIsNone(info.client_name)
        self.assertIsNone(info.scope)
        self.assertIsNone(info.audience)
        self.assertIsNone(info.resource)

    def test_read_client_info_file_name_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            client_file = Path(temp_dir) / "client.json"
            client_file.write_text(
                json.dumps(
                    {
                        "name": "mcat-cli",
                        "scopes": ["mcp:connect", "offline_access"],
                        "audience": "example-api",
                        "resource": "https://example.com/mcp",
                    }
                ),
                encoding="utf-8",
            )

            info = read_client_info_file(str(client_file))

            self.assertEqual(info.client_name, "mcat-cli")
            self.assertEqual(info.scope, "mcp:connect offline_access")
            self.assertEqual(info.audience, "example-api")
            self.assertEqual(info.resource, "https://example.com/mcp")

    def test_read_client_info_file_rejects_name_with_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            client_file = Path(temp_dir) / "client.json"
            client_file.write_text(
                json.dumps({"name": "named-client", "id": "abc"}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "client info file cannot combine name with id/client_id or secret/client_secret",
            ):
                read_client_info_file(str(client_file))

    def test_read_client_info_file_rejects_secret_without_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            client_file = Path(temp_dir) / "client.json"
            client_file.write_text(
                json.dumps({"secret": "topsecret"}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "client info file secret/client_secret requires id/client_id",
            ):
                read_client_info_file(str(client_file))

    def test_resolve_client_secret_spec_literal(self) -> None:
        self.assertEqual(resolve_client_secret_spec("plain-secret"), "plain-secret")

    def test_resolve_client_secret_spec_key_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            secret_file = Path(temp_dir) / "secret.json"
            secret_file.write_text(
                json.dumps({"client_secret": "from-file"}),
                encoding="utf-8",
            )

            resolved = resolve_client_secret_spec(f"json://{secret_file}")
            self.assertEqual(resolved, "from-file")

    def test_resolve_client_secret_spec_missing_key_spec(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "client secret KEY_SPEC not found: json://missing-file.json",
        ):
            resolve_client_secret_spec("json://missing-file.json")


if __name__ == "__main__":
    unittest.main()
