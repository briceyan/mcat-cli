from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from typing import Any, Callable

import click
import typer
from typer.core import TyperGroup

from . import auth as auth_mod
from . import mcp as mcp_mod
from .util.logging import configure_logging, parse_log_specs

APP_LOGGER = logging.getLogger("mcat.app")

GLOBAL_BOOL_FLAGS = {"--log-stderr"}
GLOBAL_OPTS_WITH_VALUE = {"--log", "--log-file"}
KNOWN_OPTS_WITH_VALUE = {
    "--log",
    "--log-file",
    "-k",
    "--key-ref",
    "-o",
    "--out-key-ref",
    "--out",
    "--sess-info-file",
    "--state",
    "-s",
    "--session",
    "-i",
    "--input",
    "--cursor",
}
AUTH_OUT_SELF_FLAG = "--out-key-ref-self"

ROOT_COMMAND_ORDER = {
    "auth": 0,
    "init": 1,
    "resource": 2,
    "tool": 3,
}


@dataclass(slots=True)
class Runtime:
    enabled_logs: dict[str, int]
    log_stderr: bool
    log_file: str | None


class RootHelpOrderGroup(TyperGroup):
    def list_commands(self, ctx: click.Context) -> list[str]:
        names = list(super().list_commands(ctx))
        return sorted(
            names, key=lambda name: (ROOT_COMMAND_ORDER.get(name, 1000), name)
        )


def _json_dump(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def emit_success(result: Any | None = None) -> None:
    payload: dict[str, Any] = {"ok": True}
    if result is not None:
        payload["result"] = result
    typer.echo(_json_dump(payload))


def emit_error(message: str, *, exit_code: int = 1) -> None:
    typer.echo(_json_dump({"ok": False, "error": str(message)}))
    raise typer.Exit(code=exit_code)


def _run_json_command(fn: Callable[[], Any]) -> None:
    try:
        result = fn()
    except typer.Exit:
        raise
    except NotImplementedError as exc:
        emit_error(str(exc) or "not implemented")
    except ValueError as exc:
        emit_error(str(exc) or "invalid input")
    except Exception:
        APP_LOGGER.exception("Unhandled exception")
        emit_error("internal error")
    emit_success(result)


def _run_binary_stdout_command(fn: Callable[[], bytes]) -> None:
    try:
        payload = fn()
    except typer.Exit:
        raise
    except NotImplementedError as exc:
        emit_error(str(exc) or "not implemented")
    except ValueError as exc:
        emit_error(str(exc) or "invalid input")
    except Exception:
        APP_LOGGER.exception("Unhandled exception")
        emit_error("internal error")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _runtime(ctx: typer.Context) -> Runtime:
    runtime = ctx.find_root().obj
    if not isinstance(runtime, Runtime):
        raise RuntimeError("runtime not initialized")
    return runtime


def _require(value: str | None, *, param_name: str, display: str) -> str:
    if value is None or value == "":
        raise typer.BadParameter(f"{display} is required", param_hint=param_name)
    return value


def _resolve_out_key_ref(
    *,
    input_key_ref: str,
    out_key_ref: str | None,
    out_key_ref_self: bool,
) -> str | None:
    if out_key_ref_self and out_key_ref is not None:
        raise typer.BadParameter(
            "use `-o` without a value or `-o KEY_REF`, not both",
            param_hint="-o",
        )
    if out_key_ref_self:
        return input_key_ref
    return out_key_ref


def normalize_cli_argv(argv: list[str]) -> list[str]:
    """Normalize argv for flexible option placement and auth `-o [KEY_REF]`.

    1) Hoist known root/global log options.
    2) Rewrite direct `auth ENDPOINT ...` to hidden `auth start ...`.
    3) Rewrite bare `auth ... -o` to an internal flag.
    """

    argv = _hoist_global_log_options(argv)
    argv = _normalize_auth_start_alias(argv)
    return _normalize_auth_out_option(argv)


def _hoist_global_log_options(argv: list[str]) -> list[str]:
    """Allow known root/global log options to appear later in argv.

    Click/Typer root options normally need to appear before the first subcommand.
    We pre-scan argv and hoist the known global logging options while preserving
    relative order of both the hoisted tokens and the remaining tokens.

    Parsing stops at `--` so values after that remain untouched.
    """

    if not argv:
        return argv

    hoisted: list[str] = []
    rest: list[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            rest.extend(argv[i:])
            break

        name, sep, _value = token.partition("=")

        if name in GLOBAL_BOOL_FLAGS and (sep == "" or token == name):
            hoisted.append(token)
            i += 1
            continue

        if name in GLOBAL_OPTS_WITH_VALUE and sep == "=":
            hoisted.append(token)
            i += 1
            continue

        if token in GLOBAL_OPTS_WITH_VALUE:
            if i + 1 < len(argv):
                hoisted.extend([token, argv[i + 1]])
                i += 2
                continue
            # Let Click/Typer produce the usage error if the value is missing.
            rest.append(token)
            i += 1
            continue

        if name in KNOWN_OPTS_WITH_VALUE and sep == "=":
            rest.append(token)
            i += 1
            continue

        if token in KNOWN_OPTS_WITH_VALUE:
            rest.append(token)
            if i + 1 < len(argv):
                rest.append(argv[i + 1])
                i += 2
            else:
                i += 1
            continue

        rest.append(token)
        i += 1

    if not hoisted:
        return argv
    return [*hoisted, *rest]


def _normalize_auth_out_option(argv: list[str]) -> list[str]:
    """Support `auth -o [KEY_REF]` where bare `-o` means "same as -k".

    Bare `-o` is only recognized when no value token follows (end, `--`, or another
    option). If a non-option token follows, it is treated as the explicit `KEY_REF`.
    """

    if not argv:
        return argv

    # Find root command after hoisted global options.
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            return argv
        name, sep, _value = token.partition("=")
        if name in GLOBAL_BOOL_FLAGS and (sep == "" or token == name):
            i += 1
            continue
        if name in GLOBAL_OPTS_WITH_VALUE and sep == "=":
            i += 1
            continue
        if token in GLOBAL_OPTS_WITH_VALUE:
            i += 2
            continue
        break

    if i >= len(argv) or argv[i] != "auth":
        return argv

    out: list[str] = argv[: i + 1]
    j = i + 1
    while j < len(argv):
        token = argv[j]
        if token == "--":
            out.extend(argv[j:])
            break

        if token in {"-o", "--out-key-ref"}:
            next_token = argv[j + 1] if j + 1 < len(argv) else None
            if next_token is None or next_token == "--" or next_token.startswith("-"):
                out.append(AUTH_OUT_SELF_FLAG)
                j += 1
                continue
            out.append(token)
            out.append(next_token)
            j += 2
            continue

        out.append(token)
        j += 1

    return out


def _normalize_auth_start_alias(argv: list[str]) -> list[str]:
    """Rewrite `mcat auth ENDPOINT ...` to `mcat auth start ENDPOINT ...`.

    `auth` is implemented as a sub-typer with subcommands. We preserve the desired
    UX by inserting a hidden `start` subcommand when the auth invocation is not
    clearly targeting a named subcommand (currently `continue`) or help.
    """

    if not argv:
        return argv

    # Find root command after hoisted globals.
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            return argv
        name, sep, _value = token.partition("=")
        if name in GLOBAL_BOOL_FLAGS and (sep == "" or token == name):
            i += 1
            continue
        if name in GLOBAL_OPTS_WITH_VALUE and sep == "=":
            i += 1
            continue
        if token in GLOBAL_OPTS_WITH_VALUE:
            i += 2
            continue
        break

    if i >= len(argv) or argv[i] != "auth":
        return argv

    # If `auth` is the last token or followed by help, leave as group help.
    if i + 1 >= len(argv):
        return argv
    if argv[i + 1] in {"--help", "-h"}:
        return argv

    # Scan auth args to locate the first non-option token after skipping option values.
    j = i + 1
    while j < len(argv):
        token = argv[j]
        if token == "--":
            return argv

        if token in {"--wait", AUTH_OUT_SELF_FLAG}:
            j += 1
            continue

        if token in {"-k", "--key-ref", "-o", "--out-key-ref", "--state"}:
            j += 2
            continue

        if (
            token.startswith("--key-ref=")
            or token.startswith("--out-key-ref=")
            or token.startswith("--state=")
        ):
            j += 1
            continue

        if token.startswith("-"):
            j += 1
            continue

        if token in {"continue", "start"}:
            return argv

        return [*argv[: i + 1], "start", *argv[i + 1 :]]

    return argv


app = typer.Typer(
    cls=RootHelpOrderGroup,
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
    help="Concise CLI for MCP authentication, resources, and tool calls.",
)
auth_app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
    help="Authentication commands.",
)
tool_app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
    help="MCP tool commands.",
)
resource_app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
    help="MCP resource commands.",
)
resource_template_app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
    help="MCP resource template commands.",
)
init_app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
    context_settings={"allow_interspersed_args": True},
    help="Initialize MCP session info files.",
)
app.add_typer(auth_app, name="auth")
app.add_typer(init_app, name="init")
app.add_typer(resource_app, name="resource")
app.add_typer(tool_app, name="tool")
resource_app.add_typer(resource_template_app, name="template")


@app.callback()
def main_callback(
    ctx: typer.Context,
    log_specs: list[str] | None = typer.Option(
        None,
        "--log",
        help="Enable logs by domain (`app`, `auth`, `mcp`) optionally with `:LEVEL`.",
    ),
    log_stderr: bool = typer.Option(
        False,
        "--log-stderr",
        help="Emit enabled logs to stderr.",
    ),
    log_file: str | None = typer.Option(
        None,
        "--log-file",
        help="Write enabled logs to this file.",
        metavar="PATH",
    ),
) -> None:
    specs = log_specs or []
    try:
        enabled_logs = parse_log_specs(specs)
        configure_logging(
            enabled=enabled_logs, log_stderr=log_stderr, log_file=log_file
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    ctx.obj = Runtime(
        enabled_logs=enabled_logs, log_stderr=log_stderr, log_file=log_file
    )
    APP_LOGGER.debug("runtime initialized")


@auth_app.callback()
def auth_group() -> None:
    return


@auth_app.command("start", hidden=True)
def auth_start(
    ctx: typer.Context,
    endpoint: str | None = typer.Argument(None, metavar="ENDPOINT"),
    key_ref: str | None = typer.Option(None, "-k", "--key-ref", metavar="KEY_REF"),
    out_key_ref: str | None = typer.Option(
        None, "-o", "--out-key-ref", metavar="KEY_REF"
    ),
    out_key_ref_self: bool = typer.Option(False, AUTH_OUT_SELF_FLAG, hidden=True),
    state_file: str | None = typer.Option(None, "--state", metavar="AUTH_STATE_FILE"),
    wait: bool = typer.Option(False, "--wait", help="Wait for auth completion."),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    _ = _runtime(ctx)
    endpoint = _require(endpoint, param_name="ENDPOINT", display="ENDPOINT")
    key_ref = _require(key_ref, param_name="--key-ref", display="KEY_REF")
    out_key_ref = _resolve_out_key_ref(
        input_key_ref=key_ref,
        out_key_ref=out_key_ref,
        out_key_ref_self=out_key_ref_self,
    )
    _run_json_command(
        lambda: auth_mod.start_auth(
            endpoint=endpoint,
            key_ref=key_ref,
            out_key_ref=out_key_ref,
            state_file=state_file,
            wait=wait,
        )
    )


@auth_app.command("continue", help="Continue a previously started authentication flow.")
def auth_continue(
    ctx: typer.Context,
    state_file: str = typer.Option(..., "--state", metavar="AUTH_STATE_FILE"),
    out_key_ref: str | None = typer.Option(
        None, "-o", "--out-key-ref", metavar="KEY_REF"
    ),
    out_key_ref_self: bool = typer.Option(False, AUTH_OUT_SELF_FLAG, hidden=True),
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: auth_mod.continue_auth(
            state_file=state_file,
            out_key_ref=out_key_ref,
            out_key_ref_self=out_key_ref_self,
        )
    )


@init_app.callback(invoke_without_command=True)
def init_command(
    ctx: typer.Context,
    endpoint: str | None = typer.Argument(None, metavar="ENDPOINT"),
    key_ref: str | None = typer.Option(None, "-k", "--key-ref", metavar="KEY_REF"),
    sess_info_file: str | None = typer.Option(
        None,
        "-o",
        "--out",
        "--sess-info-file",
        metavar="SESS_INFO_FILE",
        help="Output session info file.",
    ),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    _ = _runtime(ctx)
    endpoint = _require(endpoint, param_name="ENDPOINT", display="ENDPOINT")
    key_ref = _require(key_ref, param_name="--key-ref", display="KEY_REF")
    sess_info_file = _require(
        sess_info_file, param_name="--sess-info-file", display="SESS_INFO_FILE"
    )
    _run_json_command(
        lambda: mcp_mod.init_session(
            endpoint=endpoint, key_ref=key_ref, sess_info_file=sess_info_file
        )
    )


@resource_app.command("list", help="List resources available in the MCP session.")
def resource_list(
    ctx: typer.Context,
    sess_info_file: str = typer.Option(
        ...,
        "-s",
        "--session",
        "--sess-info-file",
        metavar="SESS_INFO_FILE",
    ),
    cursor: str | None = typer.Option(None, "--cursor", metavar="CURSOR"),
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.list_resources(
            sess_info_file=sess_info_file,
            cursor=cursor,
        )
    )


@resource_app.command("read", help="Read a resource by URI.")
def resource_read(
    ctx: typer.Context,
    uri: str = typer.Argument(..., metavar="URI"),
    sess_info_file: str = typer.Option(
        ...,
        "-s",
        "--session",
        "--sess-info-file",
        metavar="SESS_INFO_FILE",
    ),
    out_file: str | None = typer.Option(
        None,
        "-o",
        "--out",
        metavar="FILE",
        help="Write decoded content to FILE, or `-` for decoded stdout.",
    ),
) -> None:
    _ = _runtime(ctx)
    if out_file == "-":
        _run_binary_stdout_command(
            lambda: mcp_mod.read_resource_decoded_bytes(
                uri=uri,
                sess_info_file=sess_info_file,
            )[0]
        )
        return

    if out_file is None:
        _run_json_command(
            lambda: mcp_mod.read_resource(
                uri=uri,
                sess_info_file=sess_info_file,
            )
        )
        return

    _run_json_command(
        lambda: mcp_mod.save_resource(
            uri=uri,
            sess_info_file=sess_info_file,
            out_file=out_file,
        )
    )


@resource_template_app.command(
    "list",
    help="List resource templates available in the MCP session.",
)
def resource_template_list(
    ctx: typer.Context,
    sess_info_file: str = typer.Option(
        ...,
        "-s",
        "--session",
        "--sess-info-file",
        metavar="SESS_INFO_FILE",
    ),
    cursor: str | None = typer.Option(None, "--cursor", metavar="CURSOR"),
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.list_resource_templates(
            sess_info_file=sess_info_file,
            cursor=cursor,
        )
    )


@tool_app.command("list", help="List tools available in the MCP session.")
def tool_list(
    ctx: typer.Context,
    sess_info_file: str = typer.Option(
        ...,
        "-s",
        "--session",
        "--sess-info-file",
        metavar="SESS_INFO_FILE",
    ),
) -> None:
    _ = _runtime(ctx)
    _run_json_command(lambda: mcp_mod.list_tools(sess_info_file=sess_info_file))


@tool_app.command("call", help="Call an MCP tool with JSON/JSON5 arguments.")
def tool_call(
    ctx: typer.Context,
    tool_name: str = typer.Argument(..., metavar="TOOL_NAME"),
    args_input: str = typer.Option(..., "-i", "--input", metavar="ARGS"),
    sess_info_file: str = typer.Option(
        ...,
        "-s",
        "--session",
        "--sess-info-file",
        metavar="SESS_INFO_FILE",
    ),
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.call_tool(
            tool_name=tool_name,
            args_input=args_input,
            sess_info_file=sess_info_file,
        )
    )


def main() -> None:
    normalized = normalize_cli_argv(sys.argv[1:])
    if normalized != sys.argv[1:]:
        sys.argv = [sys.argv[0], *normalized]
    app()
