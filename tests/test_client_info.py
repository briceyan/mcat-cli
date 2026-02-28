from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.client_info import ClientInfo, read_client_info


class ClientInfoTest(unittest.TestCase):
    def test_read_client_info_empty_ref(self) -> None:
        info = read_client_info(None)
        self.assertEqual(info, ClientInfo())

    def test_read_client_info_name_mode(self) -> None:
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

            info = read_client_info(str(client_file))

            self.assertEqual(info.name, "mcat-cli")
            self.assertEqual(info.resolved_scope(), "mcp:connect offline_access")
            self.assertEqual(info.audience, "example-api")
            self.assertEqual(info.resource, "https://example.com/mcp")

    def test_read_client_info_rejects_name_with_id(self) -> None:
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
                read_client_info(str(client_file))

    def test_read_client_info_rejects_secret_without_id(self) -> None:
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
                read_client_info(str(client_file))

    def test_client_info_resolved_secret_literal(self) -> None:
        self.assertEqual(ClientInfo(secret="plain-secret").resolved_secret(), "plain-secret")

    def test_client_info_resolved_secret_key_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            secret_file = Path(temp_dir) / "secret.json"
            secret_file.write_text(
                json.dumps({"client_secret": "from-file"}),
                encoding="utf-8",
            )

            resolved = ClientInfo(secret=f"json://{secret_file}").resolved_secret()
            self.assertEqual(resolved, "from-file")


if __name__ == "__main__":
    unittest.main()
