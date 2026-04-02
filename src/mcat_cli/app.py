from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Callable

import click
import json5
import typer
from typer.core import TyperCommand, TyperGroup

from . import auth as auth_mod
from . import bridge as bridge_mod
from . import mcp as mcp_mod
from .util.logging import configure_logging, resolve_enabled_logs

APP_LOGGER = logging.getLogger("mcat.app")


VerboseOpt = Annotated[
    int,
    typer.Option(
        "-v",
        "--verbose",
        count=True,
        help="Set the default log level for standard modules. Use `-v` for info and `-vv` for debug.",
    ),
]
LogSpecsOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--log",
        help="Override specific modules (`auth:debug,mcp:info`). Comma-separated.",
    ),
]
LegacyLogStderrOpt = Annotated[
    bool,
    typer.Option(
        "--log-stderr",
        hidden=True,
    ),
]
LogOutputOpt = Annotated[
    str | None,
    typer.Option(
        "--log-output",
        help="Write logs to PATH instead of stderr.",
        metavar="PATH",
    ),
]

EndpointArg = Annotated[
    str,
    typer.Argument(..., metavar="ENDPOINT", help="Server URL."),
]
OptionalEndpointArg = Annotated[
    str | None,
    typer.Argument(metavar="ENDPOINT", help="Server URL."),
]

ConnectionFileOpt = Annotated[
    str,
    typer.Option(
        "-c",
        "--connection",
        metavar="CONNECTION_FILE",
        help="Path to connection file.",
    ),
]
AuthConnectionFileOpt = Annotated[
    str,
    typer.Option(
        "-c",
        "--connection",
        "--state",
        metavar="CONNECTION_FILE",
        help="Path to connection file.",
    ),
]

KeyRefOpt = Annotated[
    str,
    typer.Option(
        "-k", "--key-ref", metavar="KEY_REF", help="Where to read key/token from."
    ),
]
OptionalKeyRefOpt = Annotated[
    str | None,
    typer.Option(
        "-k",
        "--key-ref",
        metavar="KEY_REF",
        help="Where to read key/token from.",
    ),
]
KeyRefOverwriteOpt = Annotated[
    bool,
    typer.Option("-o", "--overwrite", help="Allow replacing an existing value."),
]

AuthCompleteOpt = Annotated[
    bool,
    typer.Option(
        "--complete",
        "--wait",
        help="Run until authorization completes and the token is stored.",
    ),
]
AuthClientRefOpt = Annotated[
    str | None,
    typer.Option(
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
AuthCallbackOpt = Annotated[
    str | None,
    typer.Option(
        "--callback",
        "--callback-url",
        metavar="URL",
        help="Public callback URL used in the OAuth authorization request.",
    ),
]
AuthListenOpt = Annotated[
    str | None,
    typer.Option(
        "--listen",
        "--callback-local-url",
        metavar="ADDR",
        help="Local callback listener address (`PORT`, `HOST:PORT`, or local `http://...` URL).",
    ),
]
CallbackProxyListenOpt = Annotated[
    str,
    typer.Option(
        "--listen",
        metavar="ADDR",
        help="Expose a callback address (`PORT`, `HOST:PORT`, or local `http://...` URL).",
    ),
]
CallbackProxyToOpt = Annotated[
    str,
    typer.Option(
        "--to",
        metavar="TARGET",
        help="Forward to a callback address (`PORT`, `HOST:PORT`, local `http://...` URL, or absolute URL).",
    ),
]
CallbackTargetListenOpt = Annotated[
    str | None,
    typer.Option(
        "--listen",
        metavar="ADDR",
        help="Resolve a callback address (`PORT`, `HOST:PORT`, or local `http://...` URL).",
    ),
]
CallbackTargetHostOpt = Annotated[
    str | None,
    typer.Option(
        "--host",
        metavar="HOST",
        help="Use HOST in the resolved target URL.",
    ),
]

SessionFileOpt = Annotated[
    str,
    typer.Option(
        "-s",
        "--session",
        metavar="SESSION_INFO_FILE",
        help="Path to session info file.",
    ),
]
InitSessionFileOpt = Annotated[
    str,
    typer.Option(
        "-s",
        "--session",
        "-o",
        "--out",
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
BridgeEndpointArg = Annotated[
    str,
    typer.Argument(
        ...,
        metavar="ENDPOINT",
        help="Local HTTP endpoint for internal bridge server command.",
    ),
]
BridgePortOpt = Annotated[
    int | None,
    typer.Option(
        "--port",
        metavar="PORT",
        help=f"Local bridge port (default: {bridge_mod.DEFAULT_BRIDGE_PORT}).",
    ),
]


@dataclass(slots=True)
class GlobalOpts:
    enabled_logs: dict[str, int]
    log_file: str | None


class HelpOnMissingParamsCommand(TyperCommand):
    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        try:
            return super().parse_args(ctx, args)
        except click.MissingParameter:
            click.echo(ctx.get_help(), color=ctx.color)
            raise click.exceptions.Exit(0) from None


class McatTopLevelGroup(TyperGroup):
    def list_commands(self, ctx: click.Context) -> list[str]:
        commands = list(super().list_commands(ctx))
        if not commands:
            return commands
        preferred_order = {"bridge": 0, "auth": 1, "init": 2}
        existing_index = {name: idx for idx, name in enumerate(commands)}
        commands.sort(
            key=lambda name: (preferred_order.get(name, 2), existing_index[name])
        )
        return commands


def auth_default(
    ctx: typer.Context,
    endpoint: OptionalEndpointArg = None,
    connection_file: AuthConnectionFileOpt = "",
    key_ref: OptionalKeyRefOpt = None,
    client: AuthClientRefOpt = None,
    client_id: AuthClientIdOpt = None,
    client_secret: AuthClientSecretOpt = None,
    client_name: AuthClientNameOpt = None,
    callback_url: AuthCallbackOpt = None,
    listen: AuthListenOpt = None,
    overwrite: KeyRefOverwriteOpt = False,
    complete: AuthCompleteOpt = False,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: auth_mod.run_auth(
            endpoint=endpoint,
            connection_file=connection_file,
            key_ref=key_ref,
            complete=complete,
            overwrite=overwrite,
            callback_url=callback_url,
            listen=listen,
            client_ref=client,
            client_id_override=client_id,
            client_secret_override=client_secret,
            client_name_override=client_name,
        )
    )


def init_default(
    ctx: typer.Context,
    connection_file: ConnectionFileOpt,
    sess_info_file: InitSessionFileOpt,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.init_session(
            connection_file=connection_file,
            sess_info_file=sess_info_file,
        )
    )


bridge_cmd = typer.Typer()


@bridge_cmd.command(
    "start",
    help="Start a stdio-to-HTTP bridge. Pass command after `--`.",
    cls=HelpOnMissingParamsCommand,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def bridge_start(
    ctx: typer.Context,
    connection_file: ConnectionFileOpt,
    port: BridgePortOpt = None,
) -> None:
    _ = _runtime(ctx)
    command = _parse_passthrough_command(ctx.args)
    _run_json_command(
        lambda: bridge_mod.bridge_start(
            connection_file=connection_file,
            port=port,
            command=command,
        )
    )


@bridge_cmd.command(
    "stop",
    help="Stop a bridge.",
    cls=HelpOnMissingParamsCommand,
)
def bridge_stop(
    ctx: typer.Context,
    connection_file: ConnectionFileOpt,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: bridge_mod.bridge_stop(connection_file=connection_file)
    )


@bridge_cmd.command(
    "status",
    help="Show status for a bridge.",
    cls=HelpOnMissingParamsCommand,
)
def bridge_status(
    ctx: typer.Context,
    connection_file: ConnectionFileOpt,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: bridge_mod.bridge_status(connection_file=connection_file)
    )


@bridge_cmd.command(
    "_serve",
    hidden=True,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def bridge_serve(
    ctx: typer.Context,
    endpoint: BridgeEndpointArg,
) -> None:
    _ = _runtime(ctx)
    command = _parse_passthrough_command(ctx.args)
    try:
        bridge_mod.run_bridge_server(endpoint=endpoint, command=command)
    except Exception as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1)


resource_cmd = typer.Typer()


@resource_cmd.command(
    "list",
    help="List resources available.",
    cls=HelpOnMissingParamsCommand,
)
def resource_list(
    ctx: typer.Context,
    sess_info_file: SessionFileOpt,
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
    cls=HelpOnMissingParamsCommand,
)
def resource_list_template(
    ctx: typer.Context,
    sess_info_file: SessionFileOpt,
    cursor: ResourceCursorOpt = None,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.list_resource_templates(
            sess_info_file=sess_info_file,
            cursor=cursor,
        )
    )


@resource_cmd.command(
    "read",
    help="Read a resource by URI.",
    cls=HelpOnMissingParamsCommand,
)
def resource_read(
    ctx: typer.Context,
    uri: ResourceUriArg,
    sess_info_file: SessionFileOpt,
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


@tool_cmd.command("list", help="List tools available.", cls=HelpOnMissingParamsCommand)
def tool_list(
    ctx: typer.Context,
    sess_info_file: SessionFileOpt,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(lambda: mcp_mod.list_tools(sess_info_file=sess_info_file))


@tool_cmd.command("call", help="Call a specific tool.", cls=HelpOnMissingParamsCommand)
def tool_call(
    ctx: typer.Context,
    tool_name: ToolNameArg,
    args_input: ToolInputOpt,
    sess_info_file: SessionFileOpt,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.call_tool(
            tool_name=tool_name,
            arguments=_parse_cli_json_object(args_input, label="ARGS"),
            sess_info_file=sess_info_file,
        )
    )


prompt_cmd = typer.Typer()


@prompt_cmd.command(
    "list",
    help="List prompts available.",
    cls=HelpOnMissingParamsCommand,
)
def prompt_list(
    ctx: typer.Context,
    sess_info_file: SessionFileOpt,
    cursor: ResourceCursorOpt = None,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.list_prompts(
            sess_info_file=sess_info_file,
            cursor=cursor,
        )
    )


@prompt_cmd.command("get", help="Get a prompt by name.", cls=HelpOnMissingParamsCommand)
def prompt_get(
    ctx: typer.Context,
    prompt_name: PromptNameArg,
    sess_info_file: SessionFileOpt,
    args_input: PromptInputOpt = None,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: mcp_mod.get_prompt(
            prompt_name=prompt_name,
            arguments=_parse_prompt_arguments(args_input),
            sess_info_file=sess_info_file,
        )
    )


def parse_global_opts(
    ctx: typer.Context,
    verbose: VerboseOpt = 0,
    log_specs: LogSpecsOpt = None,
    log_stderr: LegacyLogStderrOpt = False,
    log_file: LogOutputOpt = None,
) -> None:
    try:
        enabled_logs = resolve_enabled_logs(verbosity=verbose, specs=log_specs)
        emit_logs_to_stderr = log_stderr or (bool(enabled_logs) and not log_file)
        configure_logging(
            enabled=enabled_logs,
            log_stderr=emit_logs_to_stderr,
            log_file=log_file,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    ctx.obj = GlobalOpts(
        enabled_logs=enabled_logs,
        log_file=log_file,
    )
    APP_LOGGER.debug("runtime initialized")


conf: dict[str, Any] = {"no_args_is_help": True}
app = typer.Typer(
    cls=McatTopLevelGroup,
    add_completion=False,
    help="The model-context access tool for agents and humans.",
    callback=parse_global_opts,
    **conf,
)
app.command(
    "auth",
    help="Authorize MCP server access.",
    cls=HelpOnMissingParamsCommand,
)(auth_default)


@app.command(
    "callback-proxy",
    hidden=True,
    help="Start a simple callback relay.",
    cls=HelpOnMissingParamsCommand,
)
def callback_proxy(
    ctx: typer.Context,
    listen: CallbackProxyListenOpt,
    forward_to: CallbackProxyToOpt,
) -> None:
    _ = _runtime(ctx)
    try:
        resolved_target = auth_mod.resolve_callback_proxy_target(forward_to)
        handle = auth_mod.start_callback_proxy(listen=listen, target=resolved_target)
    except Exception as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None

    typer.echo(
        f"Callback proxy listening on {handle.listen_uri} forwarding to {handle.target_url}",
        err=True,
    )
    try:
        handle.thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        auth_mod.stop_callback_proxy(handle)


@app.command(
    "callback-target",
    hidden=True,
    help="Resolve concrete callback URLs.",
    cls=HelpOnMissingParamsCommand,
)
def callback_target(
    ctx: typer.Context,
    listen: CallbackTargetListenOpt = None,
    target_host: CallbackTargetHostOpt = None,
) -> None:
    _ = _runtime(ctx)
    _run_json_command(
        lambda: auth_mod.build_callback_target(
            listen=listen,
            target_host=target_host,
        )
    )


app.command(
    "init",
    help="Initialize MCP sessions.",
    cls=HelpOnMissingParamsCommand,
)(init_default)
app.add_typer(bridge_cmd, name="bridge", help="Bridge stdio to HTTP.", **conf)
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


def _parse_cli_json_object(input_value: str, *, label: str) -> dict[str, Any]:
    spec = input_value.strip()
    if not spec:
        raise ValueError(f"{label} is required")

    source = label
    if spec == "@-":
        source = "stdin"
        text = sys.stdin.read()
    elif spec.startswith("@"):
        path = spec[1:].strip()
        if not path:
            raise ValueError(f"invalid {label} reference: missing file path after @")
        source = path
        file_path = Path(path)
        try:
            text = file_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise ValueError(f"{label} file not found: {path}") from None
        except OSError as exc:
            raise ValueError(f"unable to read {label} file {path}: {exc}") from None
    else:
        text = input_value

    try:
        parsed = json5.loads(text)
    except Exception as exc:
        raise ValueError(f"invalid JSON/JSON5 in {source}: {exc}") from None
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be a JSON object")
    return parsed


def _parse_prompt_arguments(args_input: str | None) -> dict[str, str] | None:
    if args_input is None:
        return None
    parsed = _parse_cli_json_object(args_input, label="ARGS")
    arguments: dict[str, str] = {}
    for key, value in parsed.items():
        if not isinstance(value, str):
            raise ValueError("ARGS for prompts/get must be a JSON object of strings")
        arguments[key] = value
    return arguments


def _parse_passthrough_command(extra_args: list[str]) -> list[str]:
    args = list(extra_args)
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        raise ValueError(
            "missing command after -- (example: mcat bridge start -c local.connection.json -- codex mcp-server)"
        )
    return args


def _runtime(ctx: typer.Context) -> GlobalOpts:
    runtime = ctx.find_root().obj
    if not isinstance(runtime, GlobalOpts):
        raise RuntimeError("runtime not initialized")
    return runtime
