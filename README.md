# mcat-cli

The model-context access tool for agents and humans.

`mcat` is a concise CLI for:
- OAuth authorization against MCP servers
- MCP session initialization
- tool listing/calling
- resource listing/reading
- prompt listing/fetching

## Install

```bash
pip install mcat-cli
```

Requires Python 3.11+.

## Quick Start

1) Start OAuth authorization:

```bash
mcat auth start https://your-mcp-server.example/mcp \
  -k token.json \
  --state auth.json
```

This returns a pending result with action details (URL/code).  
Use `--wait` if you want to block until completion.

2) Complete authorization and store token:

```bash
mcat auth continue --state auth.json -k token.json
```

If `token.json` already exists, add `-o/--overwrite`.

3) Initialize an MCP session:

```bash
mcat init https://your-mcp-server.example/mcp -k token.json -o session.json
```

4) Call MCP tools/resources/prompts:

```bash
mcat tool list -s session.json
mcat tool call my_tool -i '{"foo":"bar"}' -s session.json

mcat resource list -s session.json
mcat resource list-template -s session.json
mcat resource read my://resource -s session.json

mcat prompt list -s session.json
mcat prompt get summarize -i '{"topic":"release notes"}' -s session.json
```

## KEY_REF Formats

`-k/--key-ref` accepts:
- `env://VAR`
- `.env://path:VAR`
- `.env://:VAR` (shortcut for `.env://.env:VAR`)
- `json://path`
- bare file path (same as `json://path`)

For auth flows, token output is written back to `--key-ref`.
- Missing destination is allowed (first-time auth).
- Existing destination requires `-o/--overwrite`.

## OAuth Client Config (Optional)

`mcat auth start` accepts optional client configuration inputs:
- `-c/--client path/to/client-info.json`
- `--client-id`
- `--client-secret`
- `--client-name`

Resolution order is deterministic:
1. CLI overrides
2. `--client` JSON file
3. Built-in defaults

If a resolved `client_id` exists, mcat uses static client mode and skips dynamic registration.
If no `client_id` is resolved, mcat attempts dynamic registration once using resolved
`client_name` (`--client-name` > `client.name` > default).

`--key-ref` remains token storage only. Client config is not read from key-ref.

Example client info files:

```json
{"name":"Codex"}
```

```json
{
  "id": "abc123",
  "secret": "env://FIGMA_CLIENT_SECRET",
  "scope": "mcp:connect",
  "resource": "https://mcp.figma.com/mcp"
}
```

Validation rules:
- `name` conflicts with `id`/`secret`.
- `--client-name` conflicts with `--client-id`/`--client-secret`.
- `secret` (or `--client-secret`) requires `id` (or `--client-id`).

## Output Contract

Most commands write compact JSON to stdout:

```json
{"ok":true,"result":{}}
```

```json
{"ok":false,"error":"message"}
```

Exception: `mcat resource read ... -o -` writes decoded bytes to stdout.

## Logging

Logs are opt-in:

```bash
mcat --log auth --log-stderr auth start ...
mcat --log app --log mcp --log-file mcat.log tool list -s session.json
```
