# mcat-cli Design (v1)

## Goal

`mcat-cli` provides a compact `mcat` command for interacting with MCP servers.

Design priorities:

- Agent-friendly shell usage
- Human-friendly concise output
- Stable JSON output contract
- Explicit file-based state (safe for concurrent/interleaved runs)
- Very small implementation surface (few modules)

## Principles

- `stdout` is machine-readable JSON for command results.
- `stderr` is reserved for logs and diagnostics only when enabled.
- No implicit global mutable state.
- All state is passed via command-line file paths.
- Failures return JSON and non-zero exit status.
- Implementation should stay concise and modular (`app`, `auth`, `mcp`).

## Command Surface (v1)

```bash
mcat [GLOBAL_OPTS] auth ENDPOINT -k KEY_REF [-o [OUT_KEY_REF]] [--state AUTH_STATE_FILE] [--wait]
mcat [GLOBAL_OPTS] auth continue --state AUTH_STATE_FILE [-o [OUT_KEY_REF]]

mcat [GLOBAL_OPTS] init ENDPOINT -k KEY_REF -o SESS_INFO_FILE

mcat [GLOBAL_OPTS] resource list -s SESS_INFO_FILE [--cursor CURSOR]
mcat [GLOBAL_OPTS] resource read URI -s SESS_INFO_FILE [-o FILE]
mcat [GLOBAL_OPTS] resource template list -s SESS_INFO_FILE [--cursor CURSOR]

mcat [GLOBAL_OPTS] tool list -s SESS_INFO_FILE
mcat [GLOBAL_OPTS] tool call TOOL_NAME -i ARGS -s SESS_INFO_FILE
```

Notes:

- `auth` starts an authentication flow.
- `auth continue` resumes a previously started auth flow (required for agent/interleaved usage).
- `tool call` includes `TOOL_NAME` explicitly.
- `resource read` includes `URI` explicitly and supports optional decoded output via `-o`.
- `SESS_INFO_FILE` is created by `init` and reused by `tool` commands.
- `SESS_INFO_FILE` is also reused by `resource` commands.
- `auth` defaults to non-blocking behavior; pass `--wait` to block/poll until completion.
- `auth` output key behavior:
  - no `-o`: do not overwrite any key ref
  - `-o` (no value): overwrite the input `-k` key ref
  - `-o KEY_REF`: write to a different key ref
- CLI parsing should be flexible about option positions:
  - command/subcommand options may appear before or after positional arguments (when unambiguous)
  - known root/global logging options may appear after subcommands/arguments and are normalized before parse

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

- `mcat auth ... --wait` runs end-to-end (blocks/polls until token is available).
- It may print instructions for the user to complete a browser/device step.
- Without `--wait`, it returns a pending result and can be resumed via `auth continue`.

### Agent usage

- `mcat auth ...` starts auth and returns immediately with a pending result by default.
- The result contains the user action required (URL/code, callback URL, etc.) and a state file path.
- A later `mcat auth continue --state ...` completes the process and stores/returns the token.

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

Complete (returned directly, only if no output ref is provided):

```json
{
  "ok": true,
  "result": {
    "status": "complete",
    "access_token": "...",
    "token_type": "Bearer"
  }
}
```

## Key Reference (`KEY_REF`)

`KEY_REF` indicates how secrets/tokens are read from or written to storage.

Supported forms:

- `env://VAR`
- `.env://path:VAR`
- `json://path`
- bare file path (shorthand for `json://path`)

### Semantics

- `-k / --key-ref`: read input key/token from reference
- `-o / --out-key-ref`: write output key/token to reference

Auth-specific behavior:

- `-k` may point to a non-existent key ref on first-time auth
- if `-o` is omitted, auth returns the token but does not overwrite `-k`
- if `-o` is present without a value, auth overwrites `-k`
- if `-o` has a value, auth writes to that output key ref

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
mcat resource template list -s SESS_INFO_FILE [--cursor CURSOR]
```

Mapping:

- `resource list` -> `resources/list` with optional pagination cursor.
- `resource read` -> `resources/read` with `uri` and output-mode switch via `-o`.
- `resource template list` -> `resources/templates/list` with optional cursor.

Output policy (same CLI contract):

- `resource list` result: raw `{resources, nextCursor?}`.
- `resource read` result (no `-o`): raw `{contents}` where each item is text/blob content.
- `resource template list` result: raw `{resourceTemplates, nextCursor?}`.

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

```json
{
  "version": 1,
  "session_id": "uuid-or-server-session-id",
  "key_ref": "json:///path/to/token.json",
  "endpoint": "https://example.com/mcp"
}
```

Notes:

- Versioned for forward compatibility.
- `key_ref` stores the reference, not the secret value.
- Session file is intended to be read-only after creation in v1.

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
- `auth` sub-app: start/resume authentication
- `resource` sub-app: list/read/templates (and optional watch later)
- `tool` sub-app: list/call tools
- `init` command: create session file

### Typer design notes

- Use a root callback to configure logging and shared runtime config.
- Use sub-app callbacks/context for shared options (`SESS_INFO_FILE`, etc.) where useful.
- Keep output generation centralized (single JSON success/error helpers).
- Disable pretty exceptions to avoid noisy traces and accidental secret exposure.

## Minimal Module Layout

Implementation should remain small, with three main modules:

- `src/mcat_cli/app.py`
  - Typer app and command definitions
  - JSON output helpers
  - logging setup
  - file utility helpers (atomic write / lock wrapper)
- `src/mcat_cli/auth.py`
  - auth flow start/continue
  - key ref loading/saving
  - auth provider HTTP calls
- `src/mcat_cli/mcp.py`
  - session initialization
  - resource listing/reading/template listing
  - tool listing/calling
  - MCP transport and request/response logging

Small supporting files are acceptable (e.g. `__init__.py` entry shim), but core logic should stay in these modules.

## v1 Scope Boundaries

Keep v1 intentionally narrow:

- Support device code flow only first
- Support one MCP transport first
- No token refresh unless required by the server
- No global config file
- No interactive TUI output
- No parser-level JSON help/errors requirement (normal command outputs remain JSON)

## Open Decisions (remaining)

1. Should `auth` require `--state AUTH_STATE_FILE` when not using `--wait`, or auto-generate a temp state file and return its path?
2. Should `AUTH_STATE_FILE` be deleted automatically after successful `auth continue`, or retained for audit/debugging?

## Implementation Order (recommended)

1. CLI shell (`mcat`) + JSON success/error helpers + logging scaffolding
2. `KEY_REF` parsing and read/write backends (`env`, `.env`, `json`)
3. `auth` start/continue with a stubbed provider contract
4. `init` session file creation
5. `tool list` / `tool call` MCP transport integration
6. `resource list` / `resource read` / `resource template list`
7. File locking + atomic write hardening
8. Docs/examples and smoke tests

## Feedback (Applied)

The following feedback has been incorporated into this document:

1. Simplify auth flags to `--wait` only, with default non-blocking behavior.
2. Use device code flow only for v1.
3. Define `json://path` token storage as a JSON object (for example `access_token`, `refresh_token`, expiry fields).
4. Return raw `tool call` results in v1 (defer normalization).
5. Rename `SESSION_FILE` to `SESS_INFO_FILE` to align better with `AUTH_STATE_FILE`.
6. Add MCP resources support in phases, with list/read/templates first and streaming subscriptions later.
