from __future__ import annotations

import json
import logging
import unittest
from unittest import mock

from typer.testing import CliRunner

from mcat_cli.app import app


class AppCliCompatibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_auth_accepts_legacy_option_names(self) -> None:
        with mock.patch("mcat_cli.app.auth_mod.run_auth", return_value={"status": "ok"}) as run_auth:
            result = self.runner.invoke(
                app,
                [
                    "auth",
                    "https://example.com/mcp",
                    "--state",
                    "auth.connection.json",
                    "-k",
                    "token.json",
                    "--wait",
                    "--callback-url",
                    "https://callback.example.com/callback",
                    "--callback-local-url",
                    "43123",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.stdout)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        run_auth.assert_called_once_with(
            endpoint="https://example.com/mcp",
            connection_file="auth.connection.json",
            key_ref="token.json",
            complete=True,
            overwrite=False,
            callback_url="https://callback.example.com/callback",
            listen="43123",
            client_ref=None,
            client_id_override=None,
            client_secret_override=None,
            client_name_override=None,
        )

    def test_init_accepts_legacy_output_option_names(self) -> None:
        with mock.patch("mcat_cli.app.mcp_mod.init_session", return_value={"status": "ok"}) as init_session:
            result = self.runner.invoke(
                app,
                [
                    "init",
                    "-c",
                    "auth.connection.json",
                    "-o",
                    "session.json",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.stdout)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        init_session.assert_called_once_with(
            connection_file="auth.connection.json",
            sess_info_file="session.json",
        )

    def test_top_level_help_lists_bridge_before_auth(self) -> None:
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0, msg=result.stderr)
        self.assertIn("--verbose", result.stdout)
        self.assertIn("default log level for standard", result.stdout.lower())
        self.assertIn("override specific modules", result.stdout.lower())
        self.assertIn("--log-output", result.stdout)
        self.assertNotIn("--log-file", result.stdout)
        self.assertNotIn("--install-completion", result.stdout)
        self.assertNotIn("--show-completion", result.stdout)
        commands_section = result.stdout.split("╭─ Commands ", 1)[1]
        bridge_idx = commands_section.index("bridge")
        auth_idx = commands_section.index("auth")
        init_idx = commands_section.index("init")
        self.assertLess(bridge_idx, auth_idx)
        self.assertLess(auth_idx, init_idx)

    def test_verbose_enables_default_log_domains(self) -> None:
        with (
            mock.patch("mcat_cli.app.configure_logging") as configure_logging,
            mock.patch(
                "mcat_cli.app.bridge_mod.bridge_status",
                return_value={"status": "ok"},
            ),
        ):
            result = self.runner.invoke(
                app,
                ["-v", "bridge", "status", "-c", "local.connection.json"],
            )

        self.assertEqual(result.exit_code, 0, msg=result.stderr)
        configure_logging.assert_called_once()
        self.assertEqual(
            configure_logging.call_args.kwargs["enabled"],
            {
                "app": logging.INFO,
                "auth": logging.INFO,
                "bridge": logging.INFO,
                "mcp": logging.INFO,
            },
        )
        self.assertTrue(configure_logging.call_args.kwargs["log_stderr"])
        self.assertIsNone(configure_logging.call_args.kwargs["log_file"])

    def test_log_specs_override_verbose_defaults_with_csv(self) -> None:
        with (
            mock.patch("mcat_cli.app.configure_logging") as configure_logging,
            mock.patch(
                "mcat_cli.app.bridge_mod.bridge_status",
                return_value={"status": "ok"},
            ),
        ):
            result = self.runner.invoke(
                app,
                [
                    "-v",
                    "--log",
                    "auth:debug,proxy:error",
                    "bridge",
                    "status",
                    "-c",
                    "local.connection.json",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.stderr)
        configure_logging.assert_called_once()
        self.assertEqual(
            configure_logging.call_args.kwargs["enabled"],
            {
                "app": logging.INFO,
                "auth": logging.DEBUG,
                "bridge": logging.ERROR,
                "mcp": logging.INFO,
            },
        )
        self.assertTrue(configure_logging.call_args.kwargs["log_stderr"])

    def test_log_file_disables_default_stderr_logging(self) -> None:
        with (
            mock.patch("mcat_cli.app.configure_logging") as configure_logging,
            mock.patch(
                "mcat_cli.app.bridge_mod.bridge_status",
                return_value={"status": "ok"},
            ),
        ):
            result = self.runner.invoke(
                app,
                [
                    "-v",
                    "--log-output",
                    "mcat.log",
                    "bridge",
                    "status",
                    "-c",
                    "local.connection.json",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.stderr)
        configure_logging.assert_called_once()
        self.assertFalse(configure_logging.call_args.kwargs["log_stderr"])
        self.assertEqual(configure_logging.call_args.kwargs["log_file"], "mcat.log")

    def test_hidden_callback_target_returns_json(self) -> None:
        result = self.runner.invoke(
            app,
            [
                "callback-target",
                "--listen",
                "0.0.0.0:0",
                "--host",
                "host.docker.internal",
            ],
        )

        self.assertEqual(result.exit_code, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        body = payload["result"]
        self.assertEqual(body["callback_path"], "/callback")
        self.assertGreater(body["port"], 0)
        self.assertEqual(
            body["listen_url"],
            f"http://0.0.0.0:{body['port']}/callback",
        )
        self.assertEqual(
            body["target_url"],
            f"http://host.docker.internal:{body['port']}/callback",
        )

    def test_callback_target_help_is_compact(self) -> None:
        result = self.runner.invoke(app, ["callback-target", "--help"])
        self.assertEqual(result.exit_code, 0, msg=result.stderr)
        self.assertIn("concrete callback urls", result.stdout.lower())
        self.assertIn("--listen", result.stdout)
        self.assertIn("--host", result.stdout)
        self.assertNotIn("--callback-local-url", result.stdout)
        self.assertNotIn("--target-host", result.stdout)

    def test_callback_proxy_accepts_to_listen_spec(self) -> None:
        handle = mock.Mock()
        handle.listen_uri = "http://127.0.0.1:43123/callback"
        handle.target_url = "http://127.0.0.1:43124/callback"
        handle.thread = mock.Mock()

        with (
            mock.patch(
                "mcat_cli.app.auth_mod.resolve_callback_proxy_target",
                return_value="http://127.0.0.1:43124/callback",
            ) as resolve_target,
            mock.patch(
                "mcat_cli.app.auth_mod.start_callback_proxy",
                return_value=handle,
            ) as start_proxy,
            mock.patch("mcat_cli.app.auth_mod.stop_callback_proxy") as stop_proxy,
        ):
            result = self.runner.invoke(
                app,
                [
                    "callback-proxy",
                    "--listen",
                    "43123",
                    "--to",
                    "43124",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.stderr)
        resolve_target.assert_called_once_with("43124")
        start_proxy.assert_called_once_with(
            listen="43123",
            target="http://127.0.0.1:43124/callback",
        )
        stop_proxy.assert_called_once_with(handle)

    def test_callback_proxy_help_is_compact(self) -> None:
        result = self.runner.invoke(app, ["callback-proxy", "--help"])
        self.assertEqual(result.exit_code, 0, msg=result.stderr)
        self.assertIn("simple callback relay", result.stdout.lower())
        self.assertIn("--listen", result.stdout)
        self.assertIn("--to", result.stdout)
        self.assertNotIn("--target-listen", result.stdout)
        self.assertNotIn("--target-host", result.stdout)

    def test_legacy_proxy_command_is_removed(self) -> None:
        result = self.runner.invoke(app, ["proxy", "--help"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("No such command 'proxy'", result.stderr)


if __name__ == "__main__":
    unittest.main()
