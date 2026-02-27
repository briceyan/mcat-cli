---
name: mcat
description: "Use mcat to progressively interact with a user-provided or discovered MCP endpoint: authorize, initialize a session, and run tools/resources/prompts via concise shell JSON."
---

# mcat Skill

Use this workflow when you need MCP access from shell commands.

## Install

If the `mcat` binary is not available, install package `mcat-cli`:

```bash
pip install mcat-cli
```

## Core Rules

1. Treat `stdout` as machine output.
2. Parse `{"ok":true|false,...}` for normal commands.
3. Treat non-zero exit as failure even if text looks parseable.
4. Use explicit files for state:
   - auth state: `--state AUTH_STATE_FILE`
   - session info: `-o/--out` for init, `-s/--session` for reads
5. Enable logs only when debugging; logs are opt-in and go to `stderr`/file.

## Key References (`-k/--key-ref`)

Supported formats:

- `env://VAR`
- `.env://path:VAR`
- `.env://:VAR` (shortcut for `.env://.env:VAR`)
- `json://path`
- bare file path (same as `json://path`)

Notes:

- `env://` is read-only for writes.
- For auth writes, existing destinations require `-o/--overwrite`.
- Missing key-ref destination is allowed for first-time auth.

## Standard Agent Flow

1. Authorize:

```bash
mcat auth start ENDPOINT -k KEY_REF --state AUTH_STATE_FILE
```

2. If pending, continue:

```bash
mcat auth continue --state AUTH_STATE_FILE -k KEY_REF
```

3. Initialize session:

```bash
mcat init ENDPOINT -k KEY_REF -o SESSION_INFO_FILE
```

4. Use MCP commands with the session file:

```bash
mcat tool list -s SESSION_INFO_FILE
mcat tool call TOOL_NAME -i ARGS -s SESSION_INFO_FILE

mcat resource list -s SESSION_INFO_FILE
mcat resource list-template -s SESSION_INFO_FILE
mcat resource read URI -s SESSION_INFO_FILE

mcat prompt list -s SESSION_INFO_FILE
mcat prompt get PROMPT_NAME -i ARGS -s SESSION_INFO_FILE
```

## Auth Behavior

- `auth start` may return complete immediately if the existing token in `KEY_REF` is already valid.
- If not valid, it starts OAuth and returns pending action details.
- Add `--wait` for human-driven blocking flow.

## ARGS Input

For `-i/--input`:

- `@file` -> read JSON/JSON5 from file
- `@-` -> read JSON/JSON5 from stdin
- inline JSON/JSON5

Constraints:

- `tool call`: ARGS must be a JSON object.
- `prompt get`: ARGS must be a JSON object of string values.

## Output Handling Pattern

Use a strict JSON gate:

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

- No `-o`: return JSON (`contents`) for agent parsing.
- `-o FILE`: save decoded bytes to file and return JSON metadata.
- `-o -`: write decoded bytes directly to stdout (not JSON).

## Debugging

Enable focused logs only when needed:

```bash
mcat --log auth --log-stderr auth start ...
mcat --log mcp:debug --log-file mcat.log tool call ...
```
