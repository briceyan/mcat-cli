---
name: mcat
description: "Use mcat for MCP workflows: authorize, initialize, discover capabilities, and call tools/resources/prompts with strict JSON handling."
---

# mcat Skill

Use this workflow when MCP access is needed from shell commands.

## Install

If `mcat` is missing, example install commands:

```bash
pip install mcat-cli
```

```bash
uv tool install mcat-cli
```

## Core Rules

1. Treat stdout as machine-readable output.
2. Parse `{"ok":true|false,...}` for normal commands.
3. Treat non-zero exit as failure.
4. Use explicit files:
   - connection file: `-c/--connection CONNECTION_FILE`
   - token/key destination/source: `-k/--key-ref`
   - session info: `-s/--session SESSION_INFO_FILE`
5. Start from endpoint + progressive disclosure:
   - auth/bridge start -> init -> tool list -> targeted calls
6. Keep logs off unless debugging.

## Help and Command Shape

- Top-level order is `auth`, `init`, then `tool/resource/prompt`.
- Missing required args on first-level and second-level commands prints usage/help.
- Check `mcat <command> --help` when command construction fails.

## Key Ref and Key Spec Patterns

Supported patterns:
- `env://VAR`
- `.env://path:VAR`
- `.env://:VAR`
- `json://path`
- `path` (same as `json://path`)

Notes:
- `env://` is read-only for writes.
- auth writes token to `--key-ref`.
- existing destinations require `-o/--overwrite`.

Examples:
- use token/PAT from environment:

```bash
mcat auth ENDPOINT -c conn.json -k env://MCP_TOKEN
mcat init -c conn.json -s sess.json
```

- use token/PAT from `.env`:

```bash
mcat init ENDPOINT -k .env://.env:MCP_TOKEN -o sess.json
```

For GitHub MCP use, existing PAT can be supplied through these env forms.

## Auth Flow

Default non-blocking flow:

```bash
mcat auth ENDPOINT -c CONNECTION_FILE -k KEY_REF
mcat auth -c CONNECTION_FILE --complete
```

`auth` returns action details for browser approval when the flow is pending; then resume with `auth --complete`.

Human direct flow:

```bash
mcat auth ENDPOINT -c CONNECTION_FILE -k KEY_REF --complete
```

Behavior notes:
- If existing token in `KEY_REF` is valid, `auth` may complete immediately.
- Provider error details are surfaced when available (`error_description`, `error`, `message`, `detail`, `title`).
- For callback-proxy/container flows, use `--callback URL` and optionally `--listen ADDR`.

## OAuth Client Config

Use when provider requires specific OAuth client settings (for example, pre-registered clients such as common Linear setups).

`auth` options:
- `--client CLIENT_INFO_FILE`
- `--client-id ID`
- `--client-secret KEY_SPEC`
- `--client-name NAME`

Resolution order:
1. CLI overrides
2. client file values
3. built-in defaults

Rules:
- `name` conflicts with `id`/`secret`
- `--client-name` conflicts with `--client-id`/`--client-secret`
- `secret` requires `id`

Modes:
- static client mode when `client_id` is resolved
- dynamic registration when `client_id` is not resolved (uses resolved `client_name`)

## Session Init and Stateless Servers

```bash
mcat init -c CONNECTION_FILE -s SESSION_INFO_FILE
```

If server omits `mcp-session-id`, init still succeeds and session is stored as stateless:
- `session_mode: "stateless"`
- no `session_id`

If server returns `mcp-session-id`, session is stateful.

## STDIO Bridge

```bash
mcat bridge start -c CONNECTION_FILE -- CMD [ARG...]
mcat init -c CONNECTION_FILE -s SESSION_INFO_FILE
mcat bridge stop -c CONNECTION_FILE
```

## MCP Calls

```bash
mcat tool list -s SESSION_INFO_FILE
mcat tool call TOOL_NAME -i ARGS -s SESSION_INFO_FILE

mcat resource list -s SESSION_INFO_FILE
mcat resource list-template -s SESSION_INFO_FILE
mcat resource read URI -s SESSION_INFO_FILE

mcat prompt list -s SESSION_INFO_FILE
mcat prompt get PROMPT_NAME -s SESSION_INFO_FILE -i ARGS
```

`ARGS` forms for `-i/--input`:
- inline JSON/JSON5
- `@file` (JSON/JSON5)
- `@-` (stdin)

Constraints:
- `tool call`: ARGS must be a JSON object
- `prompt get`: ARGS must be a JSON object of string values

## Output Handling Pattern

```bash
resp="$(mcat tool list -s sess.json)"
ok="$(printf '%s' "$resp" | jq -r '.ok')"
if [ "$ok" != "true" ]; then
  printf '%s\n' "$resp" | jq -r '.error' >&2
  exit 1
fi
printf '%s\n' "$resp" | jq '.result'
```

## Resource Read Modes

- no `-o`: JSON result
- `-o FILE`: save decoded bytes to file + JSON metadata
- `-o -`: decoded bytes to stdout

## Debugging

Global log options must appear before the command name.

`-v` sets the default log level for standard modules. `--log` overrides specific modules.

Info-level logs:

```bash
mcat -v auth ...
```

Debug-level logs:

```bash
mcat -vv auth ...
```

Per-module overrides:

```bash
mcat -v --log auth:debug,mcp:debug auth ...
```
