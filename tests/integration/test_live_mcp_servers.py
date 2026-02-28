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
DEFAULT_WAIT_TIMEOUT_S = _int_env("MCAT_IT_WAIT_TIMEOUT", 360)


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
        cmd = [sys.executable, "-m", "mcat_cli.main", *args]
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

    def test_github_env_key_ref_init_and_tool_list(self) -> None:
        gh_pat = (os.getenv("MCAT_IT_GH_PAT") or "").strip()
        if not gh_pat:
            self.skipTest("set MCAT_IT_GH_PAT to run GitHub integration flow")

        endpoint = (
            os.getenv("MCAT_IT_GITHUB_ENDPOINT") or "https://api.githubcopilot.com/mcp/"
        ).strip()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            env_file = temp_path / ".env"
            session_file = temp_path / "github.session.json"
            env_file.write_text(f"GH_PAT={gh_pat}\n", encoding="utf-8")

            init_result = self._run_mcat(
                ["init", endpoint, "-k", ".env://:GH_PAT", "-o", str(session_file)],
                cwd=temp_dir,
            )
            init_payload = self._assert_ok(init_result)
            self.assertTrue(session_file.exists())
            self.assertIn("result", init_payload)

            tools_result = self._run_mcat(
                ["tool", "list", "-s", str(session_file)],
                cwd=temp_dir,
            )
            tools_payload = self._assert_ok(tools_result)
            self.assertIn("result", tools_payload)

    def test_figma_auth_start_no_wait_with_client_name(self) -> None:
        endpoint = (os.getenv("MCAT_IT_FIGMA_ENDPOINT") or "https://mcp.figma.com/mcp").strip()
        client_name = (os.getenv("MCAT_IT_FIGMA_CLIENT_NAME") or "mcat-cli-it").strip()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            state_file = temp_path / "figma.auth.json"
            token_file = temp_path / "figma.token.json"

            result = self._run_mcat(
                [
                    "--log",
                    "auth:debug",
                    "auth",
                    "start",
                    endpoint,
                    "-k",
                    str(token_file),
                    "--state",
                    str(state_file),
                    "--client-name",
                    client_name,
                ],
                cwd=temp_dir,
            )

            self.assertIn(f"dynamic_client_name={client_name}", result.stderr)
            self.assertIn("dynamic_client_name_source=cli", result.stderr)

            if result.returncode == 0:
                payload = self._assert_ok(result)
                result_body = payload.get("result") or {}
                self.assertEqual(result_body.get("status"), "pending")
                self.assertIn("url", (result_body.get("action") or {}))
                self.assertTrue(state_file.exists())
                return

            payload = self._assert_error(result)
            message = str(payload.get("error") or "").lower()
            self.assertIn("dynamic client registration", message)

    def test_linear_auth_start_no_wait_default_client_name(self) -> None:
        endpoint = (os.getenv("MCAT_IT_LINEAR_ENDPOINT") or "https://mcp.linear.app/mcp").strip()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            state_file = temp_path / "linear.auth.json"
            token_file = temp_path / "linear.token.json"

            result = self._run_mcat(
                [
                    "--log",
                    "auth:debug",
                    "auth",
                    "start",
                    endpoint,
                    "-k",
                    str(token_file),
                    "--state",
                    str(state_file),
                ],
                cwd=temp_dir,
            )
            payload = self._assert_ok(result)
            result_body = payload.get("result") or {}

            self.assertEqual(result_body.get("status"), "pending")
            self.assertIn("url", (result_body.get("action") or {}))
            self.assertTrue(state_file.exists())
            self.assertIn("dynamic_client_name_source=default", result.stderr)

    @unittest.skipUnless(
        INTERACTIVE_AUTH_ENABLED,
        "set MCAT_IT_INTERACTIVE_AUTH=1 to run interactive wait/no-wait auth completion tests",
    )
    def test_linear_auth_start_wait_completes(self) -> None:
        endpoint = (os.getenv("MCAT_IT_LINEAR_ENDPOINT") or "https://mcp.linear.app/mcp").strip()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            state_file = temp_path / "linear.wait.auth.json"
            token_file = temp_path / "linear.wait.token.json"

            print("\n[interactive] Complete Linear OAuth in browser for --wait flow.", flush=True)
            result = self._run_mcat(
                [
                    "--log",
                    "auth:info",
                    "auth",
                    "start",
                    endpoint,
                    "-k",
                    str(token_file),
                    "--state",
                    str(state_file),
                    "--wait",
                ],
                cwd=temp_dir,
                timeout=DEFAULT_WAIT_TIMEOUT_S,
                stream_stderr=True,
            )
            payload = self._assert_ok(result)
            result_body = payload.get("result") or {}
            self.assertEqual(result_body.get("status"), "complete")
            self.assertTrue(token_file.exists())

    @unittest.skipUnless(
        INTERACTIVE_AUTH_ENABLED,
        "set MCAT_IT_INTERACTIVE_AUTH=1 to run interactive wait/no-wait auth completion tests",
    )
    def test_linear_auth_no_wait_then_continue_completes(self) -> None:
        endpoint = (os.getenv("MCAT_IT_LINEAR_ENDPOINT") or "https://mcp.linear.app/mcp").strip()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            state_file = temp_path / "linear.async.auth.json"
            token_file = temp_path / "linear.async.token.json"

            start_result = self._run_mcat(
                [
                    "--log",
                    "auth:debug",
                    "auth",
                    "start",
                    endpoint,
                    "-k",
                    str(token_file),
                    "--state",
                    str(state_file),
                ],
                cwd=temp_dir,
            )
            start_payload = self._assert_ok(start_result)
            start_body = start_payload.get("result") or {}
            self.assertEqual(start_body.get("status"), "pending")
            action_url = ((start_body.get("action") or {}).get("url") or "").strip()
            self.assertTrue(action_url, msg=f"missing action url in payload: {start_payload}")

            print(
                "\n[interactive] Open this URL while auth continue is running:\n"
                f"{action_url}\n",
                flush=True,
            )
            continue_result = self._run_mcat(
                [
                    "--log",
                    "auth:info",
                    "auth",
                    "continue",
                    "--state",
                    str(state_file),
                    "-k",
                    str(token_file),
                ],
                cwd=temp_dir,
                timeout=DEFAULT_WAIT_TIMEOUT_S,
                stream_stderr=True,
            )
            continue_payload = self._assert_ok(continue_result)
            continue_body = continue_payload.get("result") or {}
            self.assertEqual(continue_body.get("status"), "complete")
            self.assertTrue(token_file.exists())


if __name__ == "__main__":
    unittest.main()
