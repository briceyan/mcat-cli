# mcat-cli Design (v1)

## Goal

`mcat-cli` provides a compact `mcat` command for interacting with MCP servers.

Design priorities:

- Agent-friendly shell usage
- Human-friendly concise output
- Stable JSON output contract
- Explicit file-based state (safe for concurrent/interleaved runs)
- Very small implementation surface (few modules)
- Multi-transport endpoint model (HTTP and local Unix socket)

## Principles

- `stdout` is machine-readable JSON for command results.
- `stderr` is reserved for logs and diagnostics only when enabled.
- No implicit global mutable state.
- All state is passed via command-line file paths.
- Failures return JSON and non-zero exit status.
- Implementation should stay concise and modular (`app`, `auth`, `proxy`, `mcp`).

## Command Surface (v1)

```bash
mcat [GLOBAL_OPTS] auth start ENDPOINT -k KEY_REF --state AUTH_STATE_FILE [--wait] [-o] [-c CLIENT_INFO_FILE] [--client-id CLIENT_ID] [--client-secret KEY_SPEC] [--client-name CLIENT_NAME]
mcat [GLOBAL_OPTS] auth continue --state AUTH_STATE_FILE -k KEY_REF [-o]

mcat [GLOBAL_OPTS] proxy up unix:///path/to/stdio.sock -- CMD [ARG...]
mcat [GLOBAL_OPTS] proxy down unix:///path/to/stdio.sock
mcat [GLOBAL_OPTS] proxy status unix:///path/to/stdio.sock

mcat [GLOBAL_OPTS] init ENDPOINT -o SESS_INFO_FILE [-k KEY_REF]

mcat [GLOBAL_OPTS] resource list -s SESS_INFO_FILE [--cursor CURSOR]
mcat [GLOBAL_OPTS] resource read URI -s SESS_INFO_FILE [-o FILE]
mcat [GLOBAL_OPTS] resource list-template -s SESS_INFO_FILE [--cursor CURSOR]

mcat [GLOBAL_OPTS] prompt list -s SESS_INFO_FILE [--cursor CURSOR]
mcat [GLOBAL_OPTS] prompt get PROMPT_NAME -s SESS_INFO_FILE [-i ARGS]

mcat [GLOBAL_OPTS] tool list -s SESS_INFO_FILE
mcat [GLOBAL_OPTS] tool call TOOL_NAME -i ARGS -s SESS_INFO_FILE
```

Notes:

- `auth` manages OAuth authorization flows.
- `auth start` begins a new authorization flow.
- `auth continue` resumes a pending authorization flow.
- `tool call` includes `TOOL_NAME` explicitly.
- `prompt get` includes `PROMPT_NAME` explicitly.
- `resource read` includes `URI` explicitly and supports optional decoded output via `-o`.
- `SESS_INFO_FILE` is created by `init` and reused by `tool` commands.
- `SESS_INFO_FILE` is also reused by `resource` commands.
- `SESS_INFO_FILE` is also reused by `prompt` commands.
- `--state AUTH_STATE_FILE` is required for `auth start` and `auth continue`.
- `-k / --key-ref` is required for `auth start` and `auth continue`.
- `ENDPOINT` may be `http://...`, `https://...`, or `unix:///...`.
- `auth` commands are only valid for HTTP(S) endpoints.
- `init` performs MCP handshake only and writes `SESS_INFO_FILE`.
- `init` with HTTP(S) endpoint requires `-k / --key-ref`.
- `init` with `unix://` endpoint requires that `proxy up` has already started a local stdio bridge on that socket.
- `auth` defaults to non-blocking behavior; pass `--wait` to block/poll until completion.
- `-o / --overwrite` allows replacing an existing `KEY_REF` value when persisting tokens.
- `auth start` supports optional OAuth client config via `-c/--client` and overrides via `--client-id`, `--client-secret`, `--client-name`.

## Endpoint Syntax (v1)

Supported endpoint forms:

- `https://host/path` (HTTP transport with OAuth support)
- `http://host/path` (HTTP transport with OAuth support)
- `unix:///absolute/path/to/socket.sock` (local Unix socket transport)

`unix://` endpoint usage is intended for local bridge mode:

```bash
mcat proxy up unix:///tmp/stdio.sock -- codex mcp-server
mcat init unix:///tmp/stdio.sock -o sess.info
mcat tool list -s sess.info
mcat proxy down unix:///tmp/stdio.sock
```

## JSON Output Contract

All normal command outputs (success or failure) go to `stdout` as JSON.

### Success (no payload)

```json
{"ok":true}
```

### Success (with payload)

```json
{"ok":true,"result":{}}
```

### Failure

```json
{"ok":false,"error":"message"}
```

Rules:

- Exit code `0` on success.
- Non-zero on failure.
- Error details are surfaced only inside the `error` field (keep concise, human-readable).
- Command help may remain standard Typer text in v1.

## Authentication Design

The CLI must support both agent-driven and human-driven use.

### Human usage

- `mcat auth start ... --wait` runs end-to-end (blocks/polls until token is available).
- It may print instructions for the user to complete a browser/device step.
- Without `--wait`, it returns a pending result and can be resumed via `auth continue`.

### Agent usage

- `mcat auth start ...` returns immediately with a pending result by default.
- The result contains the user action required (URL/code, callback URL, etc.) and a state file path.
- A later `mcat auth continue --state ... -k ...` completes the process and stores the token.

### Wait behavior

- Default behavior is equivalent to `--no-wait` (not exposed as a separate flag in v1).
- `--wait` blocks/polls until the flow completes or times out.
- This keeps the CLI simpler while still supporting both agents and humans.

### Auth result shapes (recommended)

Pending:

```json
{
  "ok": true,
  "result": {
    "status": "pending",
    "state_file": "/path/to/auth-state.json",
    "action": {
      "url": "https://...",
      "code": "ABCD-EFGH"
    }
  }
}
```

Complete (stored to output key ref):

```json
{
  "ok": true,
  "result": {
    "status": "complete",
    "stored": "json:///path/to/token.json"
  }
}
```

## Key Reference (`KEY_REF`)

`KEY_REF` indicates how secrets/tokens are read from or written to storage.

Supported forms:

- `env://VAR`
- `.env://path:VAR`
- `.env://:VAR` (shortcut for `.env://.env:VAR`)
- `json://path`
- bare file path (shorthand for `json://path`)

### Semantics

- `-k / --key-ref`: key/token reference (read config/input and persist output token)
- `-o / --overwrite`: allow replacing an existing destination value

Auth-specific behavior:

- `-k` may point to a non-existent key ref on first-time auth
- if destination exists and `-o` is omitted, write fails with an explicit error
- if destination is missing, write succeeds without `-o`
- if destination exists and `-o` is provided, existing value is replaced

OAuth client config behavior:

- Optional OAuth client config is provided via `-c/--client` JSON file.
- Supported client file fields: `id` (or `client_id`), `secret` (or `client_secret`), `name` (or `client_name`), `scope`, `resource`, `audience`.
- Resolution precedence is: CLI override > `--client` file > defaults.
- If resolved `client_id` exists, use static client mode and skip dynamic client registration.
- If resolved `client_id` does not exist, attempt dynamic registration exactly once with resolved `client_name`.
- Conflict rule: `name` cannot be combined with `id`/`secret` (same for CLI options).
- `secret` requires `id` (same for `--client-secret` + `--client-id`).
- `--key-ref` is used for token read/write only, not client config.

Constraints:

- `env://VAR` is read-only (cannot persist back to the parent shell environment)
- `.env://path:VAR` is read/write
- `json://path` is read/write

### v1 simplification

For `json://path`, store the token payload as a JSON object at the file root (no JSON Pointer support in v1).

Recommended fields:

- `access_token` (required)
- `token_type` (optional)
- `refresh_token` (optional)
- `expires_at` or `expires_in` (optional)
- additional provider fields may be preserved as-is

## Tool Call Arguments (`ARGS`)

`ARGS` input forms:

- `@file` -> load JSON/JSON5 from file
- `@-` -> load JSON/JSON5 from stdin
- inline JSON5 string -> parse directly

The parsed value is sent as tool arguments to the MCP server.

For v1, `tool call` returns the raw MCP tool result in `result` (no normalization layer yet).

## Prompt Arguments (`ARGS`)

`mcat prompt get` accepts optional `-i/--input ARGS` with the same input forms:

- `@file` -> load JSON/JSON5 from file
- `@-` -> load JSON/JSON5 from stdin
- inline JSON5 string -> parse directly

Constraint for `prompts/get`:

- parsed value must be a JSON object of string values (`{str: str}`)
- non-string values should fail fast with a concise error

Output policy:

- return raw MCP `prompts/get` result in `result`
- include current `session_id` in the command result payload

## Resource Support Design (spec 2025-11-25)

The MCP resources surface introduces:

- discovery (`resources/list`)
- content fetch (`resources/read`)
- template discovery (`resources/templates/list`)
- optional subscriptions (`resources/subscribe`, `resources/unsubscribe`)
- optional notifications (`notifications/resources/list_changed`, `notifications/resources/updated`)

### v1.1 command design

```bash
mcat resource list -s SESS_INFO_FILE [--cursor CURSOR]
mcat resource read URI -s SESS_INFO_FILE [-o FILE]
mcat resource list-template -s SESS_INFO_FILE [--cursor CURSOR]
```

Mapping:

- `resource list` -> `resources/list` with optional pagination cursor.
- `resource read` -> `resources/read` with `uri` and output-mode switch via `-o`.
- `resource list-template` -> `resources/templates/list` with optional cursor.

Output policy (same CLI contract):

- `resource list` result: raw `{resources, nextCursor?}`.
- `resource read` result (no `-o`): raw `{contents}` where each item is text/blob content.
- `resource list-template` result: raw `{resourceTemplates, nextCursor?}`.

`resource read` output-mode details:

- no `-o`:
  - default agent mode
  - emit normal JSON result on `stdout` (`{"ok":true,"result":{"contents":[...]}}`)
- `-o FILE` (`FILE != -`):
  - decode MCP content and write decoded bytes to `FILE`
  - emit JSON status payload on `stdout` (for example saved path + byte count)
- `-o -`:
  - decode MCP content and write decoded bytes directly to `stdout`
  - intended for human pipe workflows (for example `... | pbcopy` or `... > file`)
  - this is an explicit exception to the default JSON-on-stdout contract

Decode rules for `resource read -o ...`:

- if content item has `text`, write UTF-8 bytes of `text`
- if content item has `blob`, base64-decode and write raw bytes
- if `contents` has exactly one item, decode it
- if `contents` has multiple items, return JSON error and require future explicit item selection

### Capability gating

During `init`, capture and persist `initialize.result.capabilities`.

Runtime checks:

- If server does not advertise `capabilities.resources`, fail resource commands with:
  - `{"ok":false,"error":"server does not advertise resources capability"}`
- For future subscription commands, require `capabilities.resources.subscribe == true`.
- For list-change watch support, require `capabilities.resources.listChanged == true`.

### Session schema extension

Extend `SESS_INFO_FILE` with optional server handshake metadata:

```json
{
  "version": 1,
  "session_id": "server-session-id",
  "key_ref": "json:///path/to/token.json",
  "endpoint": "https://example.com/mcp",
  "protocol_version": "2025-11-05",
  "server_capabilities": {
    "resources": {
      "listChanged": true,
      "subscribe": false
    }
  }
}
```

Notes:

- Keep `version` at `1`; new fields are optional/backward-compatible.
- If metadata is missing (older session files), commands may proceed and rely on JSON-RPC method errors.

### Transport and concurrency behavior

- Reuse the existing one-request-per-command pattern.
- Continue to send `Mcp-Session-Id` and persist rotated session ids from response headers.
- Pagination remains explicit via `--cursor` and returned `nextCursor`.
- Continue lock+atomic writes when session file updates are needed.

### Subscriptions (phased design)

Because the current CLI model is one-shot, async notifications are not very useful without a long-lived stream.

Phase A (now):

- Implement `list`, `read`, `template list` only.
- Do not expose `subscribe`/`unsubscribe` yet.
- Do not add a template expansion command in this phase.

Phase B (later, if needed):

- Add `mcat resource watch URI -s SESS_INFO_FILE`.
- `watch` sends `resources/subscribe`, then consumes SSE notifications until interrupted.
- Optional `--read-on-update` to auto-run `resources/read` when update notifications arrive.

## Session Info File (`SESS_INFO_FILE`)

`mcat init` writes a session file used by `tool` commands.

### Session file schema (v1)

HTTP endpoint example:

```json
{
  "version": 1,
  "transport": "http",
  "endpoint": "https://example.com/mcp",
  "key_ref": "json:///path/to/token.json",
  "session_id": "uuid-or-server-session-id"
}
```

Unix socket endpoint example:

```json
{
  "version": 1,
  "transport": "unix",
  "endpoint": "unix:///tmp/stdio.sock",
  "session_mode": "stateless",
  "proxy_control_file": "/tmp/stdio.json"
}
```

Notes:

- Versioned for forward compatibility.
- `key_ref` is required for HTTP transport sessions.
- `key_ref` is omitted for Unix socket sessions.
- Session file is the shared transport contract for `tool`/`resource`/`prompt`.

## Proxy Control File

For a socket endpoint `unix:///path/to/stdio.sock`, proxy lifecycle metadata is stored
in `/path/to/stdio.json`.

Recommended control file schema:

```json
{
  "version": 1,
  "socket": "/path/to/stdio.sock",
  "pid": 12345,
  "command": "codex",
  "args": ["mcp-server"],
  "started_at": "2026-02-28T21:00:00Z",
  "nonce": "random-token"
}
```

`proxy down` reads this file, terminates the process, and removes both
`stdio.sock` and `stdio.json`.

## Stdio Support via Unix Socket + Proxy

`proxy up unix:///... -- CMD [ARG...]` enables local stdio-backed MCP servers while
keeping `init` focused on MCP handshake.

Design model:

1. `proxy up` starts a local bridge process.
2. Bridge launches the stdio MCP command (`CMD [ARG...]`).
3. Bridge exposes a stable Unix socket at the `unix://` endpoint path.
4. `init unix:///...` performs standard MCP initialize via that socket and writes `SESS_INFO_FILE`.
5. `tool` / `resource` / `prompt` commands use the same session-file-driven flow.
6. `proxy down` ends the bridge lifecycle.

This model allows one reusable endpoint after `init` while preserving the existing
session-based command surface.

## Auth State File

`auth continue` uses an auth state file created by `auth`.

### Auth state schema (v1)

```json
{
  "version": 1,
  "endpoint": "https://example.com",
  "flow": "device_code",
  "state": {}
}
```

Notes:

- `state` is implementation-defined and may include provider-specific fields.
- This file is internal but still JSON for debuggability.

## Concurrency and Interleaving

The CLI must be safe when commands are run concurrently/interleaved by agents.

Strategy:

- No shared global state.
- All command state is explicit (`SESS_INFO_FILE`, `AUTH_STATE_FILE`, `KEY_REF` destinations).
- File writes are atomic:
  - write to temp file in the same directory
  - flush + `fsync`
  - `os.replace()` to target path
- Mutable state files (for auth resume) should be protected by a file lock when updated.
- If lock acquisition fails quickly, return JSON error instead of blocking indefinitely.

## Logging

There are three log domains:

- `app` (CLI/app orchestration)
- `auth` (auth HTTP request/response)
- `mcp` (MCP request/response)

### Defaults

- No logs emitted unless explicitly enabled.
- When enabled, logs go to `stderr` unless `--log-file` is specified (or both if allowed).
- Default level for all domains is `info`.

### Proposed global options

- `--log app[:LEVEL]` (repeatable)
- `--log auth[:LEVEL]` (repeatable)
- `--log mcp[:LEVEL]` (repeatable)
- `--log-stderr`
- `--log-file PATH`

Examples:

```bash
mcat --log app auth ...
mcat --log mcp:debug --log-file ./mcp.log tool call ...
mcat --log auth:debug --log-stderr auth ...
```

### Logging requirements

- Logs must never appear on `stdout`.
- Sensitive headers/tokens must be redacted.
- Request/response logging should be concise by default (method, URL, status, timing, IDs).
- Full payload logging (if added later) should require an explicit debug option.

## Exit Codes (v1)

Minimal exit code scheme:

- `0` success
- `1` runtime/business error (network, auth failure, server error, file lock, parse failure)
- `2` usage error (invalid CLI args)

Typer will handle parse errors; wrapper logic should preserve the non-zero exit.

## CLI Framework (Typer)

Typer is the preferred framework for v1.

### Structure

- Root app: global logging options and shared context
- `auth` sub-app: start/continue OAuth authorization flows
- `proxy` sub-app: start/stop/status stdio bridge for Unix endpoint
- `resource` sub-app: list/read/templates (and optional watch later)
- `prompt` sub-app: list/get prompts
- `tool` sub-app: list/call tools
- `init` command: create session file

### Typer design notes

- Use a root callback to configure logging and shared runtime config.
- Use sub-app callbacks/context for shared options (`SESS_INFO_FILE`, etc.) where useful.
- Keep output generation centralized (single JSON success/error helpers).
- Disable pretty exceptions to avoid noisy traces and accidental secret exposure.

## Minimal Module Layout

Implementation should remain small, with four main modules:

- `src/mcat_cli/app.py`
  - Typer app and command definitions
  - JSON output helpers
  - logging setup
  - file utility helpers (atomic write / lock wrapper)
- `src/mcat_cli/auth.py`
  - OAuth authorization flow start/continue
  - key ref loading/saving
  - auth provider HTTP calls
- `src/mcat_cli/proxy.py`
  - stdio bridge lifecycle (`up` / `down` / `status`)
  - Unix socket control-file management (`stdio.json`)
- `src/mcat_cli/mcp.py`
  - session initialization
  - resource listing/reading/template listing
  - prompt listing/fetching
  - tool listing/calling
  - MCP transport and request/response logging

Small supporting files are acceptable (for example `main.py` entrypoint and utility modules), but core logic should stay in these modules.

## v1 Scope Boundaries

Keep v1 intentionally narrow:

- Support OAuth authorization flows needed by MCP servers (device and authorization code)
- Support two MCP transports:
  - HTTP(S) endpoint
  - local Unix socket endpoint (bridge managed via `proxy` command)
- No token refresh unless required by the server
- No global config file
- No interactive TUI output
- No parser-level JSON help/errors requirement (normal command outputs remain JSON)

## Open Decisions (remaining)

1. Should `AUTH_STATE_FILE` be deleted automatically after successful `auth continue`, or retained for audit/debugging?
2. Should a future mode allow omitting `--state` and auto-generating a temp state file?
3. Should `proxy up` support auto-restart policy for the wrapped stdio process?

## Implementation Order (recommended)

1. CLI shell (`mcat`) + JSON success/error helpers + logging scaffolding
2. `KEY_REF` parsing and read/write backends (`env`, `.env`, `json`)
3. `auth` start/continue with a stubbed provider contract
4. `proxy` lifecycle for stdio bridge (`up` / `down` / `status`)
5. MCP transport integration for HTTP(S) and Unix socket endpoints
6. `init` session file creation (handshake only, both transports)
7. `resource list` / `resource read` / `resource list-template`
8. `prompt list` / `prompt get`
9. File locking + atomic write hardening
10. Docs/examples and smoke tests

## Feedback (Applied)

The following feedback has been incorporated into this document:

1. Keep explicit `auth start` / `auth continue` subcommands.
2. Use OAuth authorization terminology across CLI/docs.
3. Use `-k/--key-ref` as auth token destination with `-o/--overwrite` as explicit replacement confirmation.
4. Define `json://path` token storage as a JSON object (for example `access_token`, `refresh_token`, expiry fields).
5. Return raw `tool call` results in v1 (defer normalization).
6. Add MCP resources support in phases, with list/read/list-template first and streaming subscriptions later.
7. Add prompt command support (`prompt list`, `prompt get`) with optional argument input.
