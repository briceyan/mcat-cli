from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from typing import Annotated, Any, Callable

import typer

from . import auth as auth_mod
from . import mcp as mcp_mod
from .util.logging import configure_logging, parse_log_specs

APP_LOGGER = logging.getLogger("mcat.app")


LogSpecsOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--log",
        help="Enable logs by domain (`app`, `auth`, `mcp`) optionally with `:LEVEL`.",
    ),
]
LogStderrOpt = Annotated[
    bool,
    typer.Option(
        "--log-stderr",
        help="Emit enabled logs to stderr.",
    ),
]
LogFileOpt = Annotated[
    str | None,
    typer.Option(
        "--log-file",
        help="Write enabled logs to file.",
        metavar="PATH",
    ),
]

EndpointArg = Annotated[
    str,
    typer.Argument(..., metavar="ENDPOINT", help="Server URL."),
]

KeyRefOpt = Annotated[
    str,
    typer.Option(
        "-k", "--key-ref", metavar="KEY_REF", help="Where to read key/token from."
    ),
]
KeyRefOverwriteOpt = Annotated[
    bool,
    typer.Option("-o", "--overwrite", help="Allow replacing an existing value."),
]

AuthWaitOpt = Annotated[
    bool,
    typer.Option("--wait", help="Wait for auth completion."),
]
AuthStateFileOpt = Annotated[
    str,
    typer.Option("--state", metavar="AUTH_STATE_FILE", help="Path to auth state file."),
]
AuthClientRefOpt = Annotated[
    str | None,
    typer.Option(
        "-c",
        "--client",
        metavar="CLIENT_INFO_FILE",
        help="Path to OAuth client info JSON file.",
    ),
]
AuthClientIdOpt = Annotated[
    str | None,
    typer.Option(
        "--client-id",
        metavar="ID",
        help="OAuth client id override (static client mode).",
    ),
]
AuthClientSecretOpt = Annotated[
    str | None,
    typer.Option(
        "--client-secret",
        metavar="KEY_SPEC",
        help="OAuth client secret override (KEY_SPEC or literal; requires client id).",
    ),
]
AuthClientNameOpt = Annotated[
    str | None,
    typer.Option(
        "--client-name",
        metavar="CLIENT_NAME",
        help="Dynamic client registration name override.",
    ),
]

SessionInfoOutOpt = Annotated[
    str,
    typer.Option(
        "-o", "--out", metavar="SESSION_INFO_FILE", help="Save session info to file."
    ),
]
SessionInfoFileOpt = Annotated[
    str,
    typer.Option(
        "-s",
        "--session",
        metavar="SESSION_INFO_FILE",
        help="Path to session info file.",
    ),
]

ToolNameArg = Annotated[
    str, typer.Argument(..., metavar="TOOL_NAME", help="Tool name.")
]
ToolInputOpt = Annotated[
    str, typer.Option("-i", "--input", metavar="ARGS", help="Tool call arguments.")
]
PromptNameArg = Annotated[
    str, typer.Argument(..., metavar="PROMPT_NAME", help="Prompt name.")
]
PromptInputOpt = Annotated[
    str | None,
    typer.Option(
        "-i",
        "--input",
        metavar="ARGS",
        help="Prompt arguments (JSON/JSON5 or @file).",
    ),
]

ResourceUriArg = Annotated[
    str, typer.Argument(..., metavar="URI", help="Resource URI.")
]
ResourceCursorOpt = Annotated[
    str | None,
    typer.Option("--cursor", metavar="CURSOR", help="Fetch from last position."),
]
ResourceOutOpt = Annotated[
    str | None,
    typer.Option(
        "-o",
        "--out",
        metavar="FILE",
        help="Write resource content to FILE(`-` to stdout).",
    ),
]


@dataclass(slots=True)
class GlobalOpts:
    enabled_logs: dict[str, int]
    log_stderr: bool
    log_file: str | None


auth_cmd = typer.Typer()


@auth_cmd.command("start", help="Start an OAuth authorization flow.")
def auth_start(
    ctx: typer.Context,
    endpoint: EndpointArg,
    key_ref: KeyRefOpt,
    state_file: AuthStateFileOpt,
    client: AuthClientRefOpt = None,
    client_id: AuthClientIdOpt = None,
    client_secret: AuthClientSecretOpt = None,
    client_name: AuthClientNameOpt = None,
    overwrite: KeyRefOverwriteOpt = False,
    wait: AuthWaitOpt = False,
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    _ = _runtime(ctx)
    _run_json_command(
        lambda: auth_mod.start_auth(
            endpoint=endpoint,
            key_ref=key_ref,
            state_file=state_file,
            wait=wait,
            overwrite=overwrite,
            client_ref=client,
            client_id_override=client_id,
            client_secret_override=client_secret,
            client_name_override=client_name,
        )
    )


@auth_cmd.command("continue", help="Continue a pending OAuth authorization flow.")
def auth_continue(
    ctx: typer.Context,
    state_file: AuthStateFileOpt,
    key_ref: KeyRefOpt,
    overwrite: KeyRefOverwriteOpt = False,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: auth_mod.continue_auth(
            state_file=state_file,
            key_ref=key_ref,
            overwrite=overwrite,
        )
    )


def init_default(
    ctx: typer.Context,
    endpoint: EndpointArg,
    key_ref: KeyRefOpt,
    sess_info_file: SessionInfoOutOpt,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.init_session(
            endpoint=endpoint, key_ref=key_ref, sess_info_file=sess_info_file
        )
    )


resource_cmd = typer.Typer()


@resource_cmd.command("list", help="List resources available.")
def resource_list(
    ctx: typer.Context,
    sess_info_file: SessionInfoFileOpt,
    cursor: ResourceCursorOpt = None,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.list_resources(
            sess_info_file=sess_info_file,
            cursor=cursor,
        )
    )


@resource_cmd.command(
    "list-template",
    help="List resource templates available.",
)
def resource_list_template(
    ctx: typer.Context,
    sess_info_file: SessionInfoFileOpt,
    cursor: ResourceCursorOpt = None,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.list_resource_templates(
            sess_info_file=sess_info_file,
            cursor=cursor,
        )
    )


@resource_cmd.command("read", help="Read a resource by URI.")
def resource_read(
    ctx: typer.Context,
    uri: ResourceUriArg,
    sess_info_file: SessionInfoFileOpt,
    out_file: ResourceOutOpt = None,
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


tool_cmd = typer.Typer()


@tool_cmd.command("list", help="List tools available.")
def tool_list(
    ctx: typer.Context,
    sess_info_file: SessionInfoFileOpt,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(lambda: mcp_mod.list_tools(sess_info_file=sess_info_file))


@tool_cmd.command("call", help="Call a specific tool.")
def tool_call(
    ctx: typer.Context,
    tool_name: ToolNameArg,
    args_input: ToolInputOpt,
    sess_info_file: SessionInfoFileOpt,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.call_tool(
            tool_name=tool_name, args_input=args_input, sess_info_file=sess_info_file
        )
    )


prompt_cmd = typer.Typer()


@prompt_cmd.command("list", help="List prompts available.")
def prompt_list(
    ctx: typer.Context,
    sess_info_file: SessionInfoFileOpt,
    cursor: ResourceCursorOpt = None,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.list_prompts(
            sess_info_file=sess_info_file,
            cursor=cursor,
        )
    )


@prompt_cmd.command("get", help="Get a prompt by name.")
def prompt_get(
    ctx: typer.Context,
    prompt_name: PromptNameArg,
    sess_info_file: SessionInfoFileOpt,
    args_input: PromptInputOpt = None,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.get_prompt(
            prompt_name=prompt_name,
            args_input=args_input,
            sess_info_file=sess_info_file,
        )
    )


def parse_global_opts(
    ctx: typer.Context,
    log_specs: LogSpecsOpt = None,
    log_stderr: LogStderrOpt = False,
    log_file: LogFileOpt = None,
) -> None:
    specs = log_specs or []
    try:
        enabled_logs = parse_log_specs(specs)
        configure_logging(
            enabled=enabled_logs, log_stderr=log_stderr, log_file=log_file
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    ctx.obj = GlobalOpts(
        enabled_logs=enabled_logs, log_stderr=log_stderr, log_file=log_file
    )
    APP_LOGGER.debug("runtime initialized")


conf: dict[str, Any] = {"no_args_is_help": True}
app = typer.Typer(
    help="The model-context access tool for agents and humans.",
    callback=parse_global_opts,
    **conf,
)
app.add_typer(auth_cmd, name="auth", help="Authorize MCP server access.", **conf)
app.command("init", help="Initialize MCP sessions.")(init_default)
app.add_typer(tool_cmd, name="tool", help="Use MCP tools.", **conf)
app.add_typer(resource_cmd, name="resource", help="Use MCP resources.", **conf)
app.add_typer(prompt_cmd, name="prompt", help="Use MCP prompts.", **conf)


def _json_dump(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _emit_success(result: Any | None = None) -> None:
    payload: dict[str, Any] = {"ok": True}
    if result is not None:
        payload["result"] = result
    typer.echo(_json_dump(payload))


def _emit_error(message: str, *, exit_code: int = 1) -> None:
    typer.echo(_json_dump({"ok": False, "error": str(message)}))
    raise typer.Exit(code=exit_code)


def _run_json_command(fn: Callable[[], Any]) -> None:
    try:
        result = fn()
    except typer.Exit:
        raise
    except NotImplementedError as exc:
        _emit_error(str(exc) or "not implemented")
    except ValueError as exc:
        _emit_error(str(exc) or "invalid input")
    except Exception:
        APP_LOGGER.exception("Unhandled exception")
        _emit_error("internal error")
    _emit_success(result)


def _run_binary_stdout_command(fn: Callable[[], bytes]) -> None:
    try:
        payload = fn()
    except typer.Exit:
        raise
    except NotImplementedError as exc:
        _emit_error(str(exc) or "not implemented")
    except ValueError as exc:
        _emit_error(str(exc) or "invalid input")
    except Exception:
        APP_LOGGER.exception("Unhandled exception")
        _emit_error("internal error")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _runtime(ctx: typer.Context) -> GlobalOpts:
    runtime = ctx.find_root().obj
    if not isinstance(runtime, GlobalOpts):
        raise RuntimeError("runtime not initialized")
    return runtime
