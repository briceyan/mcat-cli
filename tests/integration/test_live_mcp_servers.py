from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GITHUB_ENDPOINT = "https://api.githubcopilot.com/mcp/"
FIGMA_ENDPOINT = "https://mcp.figma.com/mcp"
LINEAR_ENDPOINT = "https://mcp.linear.app/mcp"
FIGMA_CLIENT_NAME = "mcat-cli-it"


def _flag(name: str) -> bool:
    value = (os.getenv(name) or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


INTEGRATION_ENABLED = _flag("MCAT_IT")
INTERACTIVE_AUTH_ENABLED = _flag("MCAT_IT_INTERACTIVE_AUTH")
DEFAULT_WAIT_TIMEOUT_S = _int_env("MCAT_IT_WAIT_TIMEOUT", 420)


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    payload: dict[str, Any] | None


@unittest.skipUnless(INTEGRATION_ENABLED, "set MCAT_IT=1 to run live integration tests")
class LiveMcpServersTest(unittest.TestCase):
    def _run_mcat(
        self,
        args: list[str],
        *,
        cwd: str | None = None,
        timeout: int = 120,
        stream_stderr: bool = False,
    ) -> CommandResult:
        # Invoke the app entrypoint directly from Python.
        cmd = [sys.executable, "-c", "from mcat_cli.main import main; main()", *args]
        env = os.environ.copy()

        if stream_stderr:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=None,
                text=True,
                timeout=timeout,
                check=False,
            )
            stderr = ""
        else:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
            stderr = proc.stderr

        stdout = proc.stdout or ""
        payload: dict[str, Any] | None = None
        if stdout.strip():
            try:
                loaded = json.loads(stdout)
            except json.JSONDecodeError as exc:
                self.fail(f"command did not return JSON stdout: {exc}\nstdout={stdout}")
            if not isinstance(loaded, dict):
                self.fail(f"command stdout JSON must be object, got: {type(loaded)!r}")
            payload = loaded

        return CommandResult(
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            payload=payload,
        )

    def _assert_ok(self, result: CommandResult) -> dict[str, Any]:
        self.assertEqual(
            result.returncode,
            0,
            msg=f"expected exit 0\nstdout={result.stdout}\nstderr={result.stderr}",
        )
        self.assertIsNotNone(result.payload, msg=f"missing JSON stdout: {result.stdout}")
        payload = result.payload or {}
        self.assertTrue(payload.get("ok"), msg=f"expected ok=true payload={payload}")
        return payload

    def _assert_error(self, result: CommandResult) -> dict[str, Any]:
        self.assertNotEqual(result.returncode, 0, msg="expected non-zero exit code")
        self.assertIsNotNone(result.payload, msg=f"missing JSON stdout: {result.stdout}")
        payload = result.payload or {}
        self.assertFalse(payload.get("ok"), msg=f"expected ok=false payload={payload}")
        return payload

    def _start_no_wait_auth(
        self,
        *,
        endpoint: str,
        connection_file: Path,
        token_file: Path,
        cwd: str,
        extra_start_args: list[str] | None = None,
    ) -> CommandResult:
        args: list[str] = [
            "--log",
            "auth:debug",
            "auth",
            endpoint,
            "-c",
            str(connection_file),
            "-k",
            str(token_file),
        ]
        if extra_start_args:
            args.extend(extra_start_args)
        return self._run_mcat(args, cwd=cwd)

    def _assert_pending_payload(self, payload: dict[str, Any]) -> str:
        result_body = payload.get("result") or {}
        self.assertEqual(result_body.get("status"), "pending")
        action_url = ((result_body.get("action") or {}).get("url") or "").strip()
        self.assertTrue(action_url, msg=f"missing action.url in payload: {payload}")
        return action_url

    def test_github_auth_start_no_wait_default_client_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            connection_file = temp_path / "github.connection.json"
            token_file = temp_path / "github.token.json"

            result = self._start_no_wait_auth(
                endpoint=GITHUB_ENDPOINT,
                connection_file=connection_file,
                token_file=token_file,
                cwd=temp_dir,
            )
            payload = self._assert_ok(result)
            self._assert_pending_payload(payload)
            self.assertTrue(connection_file.exists())
            self.assertIn("dynamic_client_name_source=default", result.stderr)

    def test_figma_auth_start_no_wait_with_client_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            connection_file = temp_path / "figma.connection.json"
            token_file = temp_path / "figma.token.json"

            result = self._start_no_wait_auth(
                endpoint=FIGMA_ENDPOINT,
                connection_file=connection_file,
                token_file=token_file,
                cwd=temp_dir,
                extra_start_args=["--client-name", FIGMA_CLIENT_NAME],
            )

            self.assertIn(f"dynamic_client_name={FIGMA_CLIENT_NAME}", result.stderr)
            self.assertIn("dynamic_client_name_source=cli", result.stderr)

            if result.returncode == 0:
                payload = self._assert_ok(result)
                self._assert_pending_payload(payload)
                self.assertTrue(connection_file.exists())
                return

            payload = self._assert_error(result)
            message = str(payload.get("error") or "").lower()
            self.assertIn("dynamic client registration", message)

    def test_linear_auth_start_no_wait_default_client_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            connection_file = temp_path / "linear.connection.json"
            token_file = temp_path / "linear.token.json"

            result = self._start_no_wait_auth(
                endpoint=LINEAR_ENDPOINT,
                connection_file=connection_file,
                token_file=token_file,
                cwd=temp_dir,
            )
            payload = self._assert_ok(result)
            self._assert_pending_payload(payload)
            self.assertTrue(connection_file.exists())
            self.assertIn("dynamic_client_name_source=default", result.stderr)

    def _run_interactive_no_wait_then_continue(
        self,
        *,
        provider_name: str,
        endpoint: str,
        extra_start_args: list[str] | None = None,
        allow_start_error_contains: tuple[str, ...] = (),
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            connection_file = temp_path / f"{provider_name}.interactive.connection.json"
            token_file = temp_path / f"{provider_name}.interactive.token.json"

            start_result = self._start_no_wait_auth(
                endpoint=endpoint,
                connection_file=connection_file,
                token_file=token_file,
                cwd=temp_dir,
                extra_start_args=extra_start_args,
            )

            if start_result.returncode != 0:
                payload = self._assert_error(start_result)
                error_text = str(payload.get("error") or "")
                lowered = error_text.lower()
                if any(pat in lowered for pat in allow_start_error_contains):
                    self.skipTest(
                        f"{provider_name}: pending auth unavailable in this environment: {error_text}"
                    )
                self.fail(
                    f"{provider_name}: auth failed unexpectedly: {error_text}\n"
                    f"stderr={start_result.stderr}"
                )

            start_payload = self._assert_ok(start_result)
            action_url = self._assert_pending_payload(start_payload)

            print(
                f"\n[interactive:{provider_name}] Open this URL now, then approve access:\n"
                f"{action_url}\n",
                flush=True,
            )

            continue_result = self._run_mcat(
                [
                    "--log",
                    "auth:info",
                    "auth",
                    "-c",
                    str(connection_file),
                    "--complete",
                ],
                cwd=temp_dir,
                timeout=DEFAULT_WAIT_TIMEOUT_S,
                stream_stderr=True,
            )
            continue_payload = self._assert_ok(continue_result)
            continue_body = continue_payload.get("result") or {}
            self.assertEqual(continue_body.get("status"), "complete")
            self.assertTrue(token_file.exists(), msg=f"{provider_name}: token not written")

    @unittest.skipUnless(
        INTERACTIVE_AUTH_ENABLED,
        "set MCAT_IT_INTERACTIVE_AUTH=1 to run interactive auth completion tests",
    )
    def test_github_auth_no_wait_then_continue_completes(self) -> None:
        self._run_interactive_no_wait_then_continue(
            provider_name="github",
            endpoint=GITHUB_ENDPOINT,
            # If GitHub app/client setup is not accepted in current account/env,
            # skip instead of hard-failing the whole integration run.
            allow_start_error_contains=("invalid", "client_id", "unauthorized"),
        )

    @unittest.skipUnless(
        INTERACTIVE_AUTH_ENABLED,
        "set MCAT_IT_INTERACTIVE_AUTH=1 to run interactive auth completion tests",
    )
    def test_figma_auth_no_wait_then_continue_completes(self) -> None:
        self._run_interactive_no_wait_then_continue(
            provider_name="figma",
            endpoint=FIGMA_ENDPOINT,
            extra_start_args=["--client-name", FIGMA_CLIENT_NAME],
            allow_start_error_contains=("dynamic client registration",),
        )

    @unittest.skipUnless(
        INTERACTIVE_AUTH_ENABLED,
        "set MCAT_IT_INTERACTIVE_AUTH=1 to run interactive auth completion tests",
    )
    def test_linear_auth_no_wait_then_continue_completes(self) -> None:
        self._run_interactive_no_wait_then_continue(
            provider_name="linear",
            endpoint=LINEAR_ENDPOINT,
        )


if __name__ == "__main__":
    unittest.main()
