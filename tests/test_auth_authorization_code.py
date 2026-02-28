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

    def test_start_authorization_code_without_wait_returns_pending(self) -> None:
        callback = mock.Mock()
        callback.redirect_uri = "http://127.0.0.1:43123/callback"

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
            mock.patch.object(auth_mod, "_default_auth_state_file", return_value="tmp-auth.json"),
            mock.patch.object(auth_mod, "_write_auth_state_file") as write_state,
            mock.patch.object(auth_mod, "_wait_for_oauth_callback") as wait_cb,
            mock.patch.object(auth_mod, "_exchange_authorization_code") as exchange_cb,
            mock.patch.object(auth_mod, "_finalize_token_result") as finalize_cb,
            mock.patch.object(auth_mod, "_print_wait_instructions") as print_instr,
        ):
            secrets_mod.token_urlsafe.return_value = "oauth-state-1"
            result = auth_mod._start_auth_authorization_code(
                endpoint="https://mcp.linear.app/mcp",
                key_ref="json://token.json",
                state_file=None,
                wait=False,
                overwrite=False,
                client_cfg=self._client_cfg(),
                oauth_meta=self._oauth_meta(),
            )

        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["state_file"], "tmp-auth.json")
        self.assertEqual(result["action"]["url"], "https://mcp.linear.app/authorize?x=1")
        wait_cb.assert_not_called()
        exchange_cb.assert_not_called()
        finalize_cb.assert_not_called()
        print_instr.assert_not_called()

        self.assertEqual(write_state.call_count, 1)
        written_path, written_doc = write_state.call_args.args
        self.assertEqual(written_path, "tmp-auth.json")
        self.assertEqual(written_doc["flow"], "authorization_code")
        self.assertEqual(written_doc["state"]["redirect_uri"], callback.redirect_uri)
        self.assertEqual(
            written_doc["state"]["authorization_url"],
            "https://mcp.linear.app/authorize?x=1",
        )
        stop_cb.assert_called_once_with(callback)

    def test_pending_result_uses_authorization_url(self) -> None:
        result = auth_mod._pending_result(
            state_file="auth-state.json",
            state={"authorization_url": "https://mcp.linear.app/authorize?x=1"},
        )
        self.assertEqual(
            result,
            {
                "status": "pending",
                "state_file": "auth-state.json",
                "action": {"url": "https://mcp.linear.app/authorize?x=1"},
            },
        )


if __name__ == "__main__":
    unittest.main()
