---
name: mcat
description: "Use mcat to authorize against MCP endpoints, initialize sessions, and run tools/resources/prompts with strict JSON output handling."
---

# mcat Skill

Use this workflow when you need MCP access from shell commands.

## Install

If `mcat` is missing:

```bash
pip install mcat-cli
```

## Core Rules

1. Treat stdout as machine-readable output.
2. Parse `{"ok":true|false,...}` for normal commands.
3. Treat non-zero exit as failure.
4. Use explicit files:
   - auth state: `--state AUTH_STATE_FILE`
   - session info: `-o/--out` for `init`, `-s/--session` for follow-up commands
5. Enable logs only for debugging (`--log ...`).

## Help / Usage Behavior

- Top-level command order is `auth`, then `init`, then `tool/resource/prompt`.
- Missing required args on first-level and second-level commands prints usage/help.
- Prefer checking `mcat <command> --help` when command construction fails.

## Key Ref (`-k/--key-ref`)

Supported formats:
- `env://VAR`
- `.env://path:VAR`
- `.env://:VAR`
- `json://path`
- bare path (same as `json://path`)

Notes:
- `env://` is read-only for writes.
- auth writes token back to `--key-ref`.
- existing key destination needs `-o/--overwrite`.

## Auth Flow

Standard flow:

```bash
mcat auth start ENDPOINT -k KEY_REF --state AUTH_STATE_FILE
mcat auth continue --state AUTH_STATE_FILE -k KEY_REF
```

Human-interactive blocking flow:

```bash
mcat auth start ENDPOINT -k KEY_REF --state AUTH_STATE_FILE --wait
```

Behavior notes:
- If existing token in `KEY_REF` is valid, `auth start` can finish immediately.
- OAuth/provider errors include provider detail when available (`error_description`, `error`, `message`, etc.).

## Auth Client Config

`auth start` supports:
- `-c/--client CLIENT_INFO_FILE`
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

## Session Init + Stateless Servers

```bash
mcat init ENDPOINT -k KEY_REF -o SESSION_INFO_FILE
```

If server omits `mcp-session-id`, init still succeeds and session is saved with:
- `session_mode: "stateless"`
- no `session_id`

Stateful servers include `session_id` and use `session_mode: "stateful"`.

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

## Debugging

```bash
mcat --log auth:debug --log-stderr auth start ...
mcat --log mcp:debug --log-file mcat.log tool call ...
```
