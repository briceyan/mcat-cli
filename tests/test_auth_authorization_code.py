from __future__ import annotations

import unittest
from unittest import mock

from mcat_cli import auth as auth_mod


class AuthAuthorizationCodeFlowTest(unittest.TestCase):
    @staticmethod
    def _client_cfg() -> auth_mod.ClientConfig:
        return auth_mod.ClientConfig(
            client_id="mcat-cli",
            client_secret=None,
            scope=None,
            audience=None,
            resource=None,
            use_dynamic_registration=True,
            dynamic_client_name="mcat-cli",
            dynamic_client_name_source="default",
        )

    @staticmethod
    def _oauth_meta() -> dict[str, str]:
        return {
            "issuer": "https://mcp.linear.app",
            "authorization_endpoint": "https://mcp.linear.app/authorize",
            "token_endpoint": "https://mcp.linear.app/token",
        }

    def test_start_authorization_code_without_complete_returns_pending(self) -> None:
        callback = mock.Mock()
        callback.redirect_uri = "http://127.0.0.1:43123/callback"
        callback.listen_uri = "http://127.0.0.1:43123/callback"

        conn_doc = {
            "version": 2,
            "kind": "http",
            "endpoint": "https://mcp.linear.app/mcp",
            "key_ref": "json://token.json",
            "flow": None,
            "state": {},
        }

        with (
            mock.patch.object(
                auth_mod, "_start_oauth_callback_listener", return_value=callback
            ),
            mock.patch.object(auth_mod, "_stop_oauth_callback_listener") as stop_cb,
            mock.patch.object(
                auth_mod,
                "_resolve_client_for_authorization_code",
                return_value={"client_id": "client-123", "client_secret": None},
            ),
            mock.patch.object(auth_mod, "_generate_pkce_verifier", return_value="verifier"),
            mock.patch.object(auth_mod, "_pkce_challenge_s256", return_value="challenge"),
            mock.patch.object(auth_mod, "secrets") as secrets_mod,
            mock.patch.object(
                auth_mod,
                "_build_authorization_request_url",
                return_value="https://mcp.linear.app/authorize?x=1",
            ),
            mock.patch.object(auth_mod, "_write_connection_file") as write_connection,
            mock.patch.object(auth_mod, "_wait_for_oauth_callback") as wait_cb,
            mock.patch.object(auth_mod, "_exchange_authorization_code") as exchange_cb,
            mock.patch.object(auth_mod, "_finalize_token_result") as finalize_cb,
            mock.patch.object(auth_mod, "_print_wait_instructions") as print_instr,
        ):
            secrets_mod.token_urlsafe.return_value = "oauth-state-1"
            result = auth_mod._start_auth_authorization_code(
                connection_file="tmp.connection.json",
                conn_doc=conn_doc,
                key_ref="json://token.json",
                complete=False,
                overwrite=False,
                callback_url=None,
                listen=None,
                client_cfg=self._client_cfg(),
                oauth_meta=self._oauth_meta(),
            )

        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["connection_file"], "tmp.connection.json")
        self.assertEqual(result["action"]["url"], "https://mcp.linear.app/authorize?x=1")
        self.assertEqual(
            result["callback"],
            {
                "public_url": "http://127.0.0.1:43123/callback",
                "listen_url": "http://127.0.0.1:43123/callback",
            },
        )
        wait_cb.assert_not_called()
        exchange_cb.assert_not_called()
        finalize_cb.assert_not_called()
        print_instr.assert_not_called()

        self.assertEqual(write_connection.call_count, 1)
        written_path, written_doc = write_connection.call_args.args
        self.assertEqual(written_path, "tmp.connection.json")
        self.assertEqual(written_doc["flow"], "authorization_code")
        self.assertEqual(
            written_doc["state"]["oauth_redirect_uri"],
            callback.redirect_uri,
        )
        self.assertEqual(written_doc["state"]["listen_uri"], callback.listen_uri)
        self.assertEqual(
            written_doc["state"]["authorization_url"],
            "https://mcp.linear.app/authorize?x=1",
        )
        stop_cb.assert_called_once_with(callback)

    def test_pending_result_uses_authorization_url_and_callback_info(self) -> None:
        result = auth_mod._pending_result(
            connection_file="auth.connection.json",
            conn_doc={"kind": "http"},
            state={
                "authorization_url": "https://mcp.linear.app/authorize?x=1",
                "oauth_redirect_uri": "https://proxy.example.com/callback",
                "listen_uri": "http://0.0.0.0:43123/callback",
            },
        )
        self.assertEqual(
            result,
            {
                "status": "pending",
                "connection_file": "auth.connection.json",
                "action": {"url": "https://mcp.linear.app/authorize?x=1"},
                "callback": {
                    "public_url": "https://proxy.example.com/callback",
                    "listen_url": "http://0.0.0.0:43123/callback",
                },
                "kind": "http",
            },
        )


if __name__ == "__main__":
    unittest.main()
