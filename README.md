# mcat-cli

The model-context access tool for agents and humans.

`mcat` is a small CLI for OAuth + MCP:
- authorize (`auth start` / `auth continue`)
- initialize session (`init`)
- use tools/resources/prompts (`tool`, `resource`, `prompt`)

## Install

```bash
pip install mcat-cli
```

Requires Python 3.11+.

## Minimal Flow

1. Authorize (recommended for manual browser flow):

```bash
mcat auth start https://your-mcp-server.example/mcp \
  -k token.json \
  --state auth.json \
  --wait
```

Without `--wait`, `auth start` returns pending state and you can finish later:

```bash
mcat auth continue --state auth.json -k token.json
```

2. Initialize session:

```bash
mcat init https://your-mcp-server.example/mcp -k token.json -o session.json
```

3. Use MCP APIs:

```bash
mcat tool list -s session.json
mcat tool call TOOL_NAME -i '{"key":"value"}' -s session.json

mcat resource list -s session.json
mcat resource read RESOURCE_URI -s session.json

mcat prompt list -s session.json
mcat prompt get PROMPT_NAME -s session.json -i '{"arg":"value"}'
```

## Key Ref (`-k/--key-ref`)

Supported formats:
- `env://VAR`
- `.env://path:VAR`
- `.env://:VAR` (same as `.env://.env:VAR`)
- `json://path`
- bare file path (same as `json://path`)

Notes:
- auth writes token back to `--key-ref`
- existing destination needs `-o/--overwrite`
- `env://` is read-only for writes

## Optional OAuth Client Config

`auth start` accepts optional client inputs:
- `-c/--client CLIENT_INFO_FILE`
- `--client-id ID`
- `--client-secret KEY_SPEC`
- `--client-name NAME`

Resolution order:
1. CLI overrides
2. `--client` file
3. built-in default

Modes:
- static client mode: resolved `client_id` present
- dynamic registration: no resolved `client_id`, uses resolved `client_name`

Validation:
- `name` conflicts with `id`/`secret`
- `--client-name` conflicts with `--client-id`/`--client-secret`
- `secret` requires `id`

Example client file (dynamic registration):

```json
{"name":"your-public-client-name"}
```

Example client file (static client):

```json
{
  "id": "your-client-id",
  "secret": "env://OAUTH_CLIENT_SECRET",
  "scope": "mcp:connect",
  "resource": "https://your-mcp-server.example/mcp"
}
```

## Output and Logging

Most commands emit JSON to stdout:

```json
{"ok":true,"result":{}}
```

```json
{"ok":false,"error":"message"}
```

Debug logs are opt-in:

```bash
mcat --log auth:debug --log-stderr auth start ...
mcat --log mcp:debug --log-file mcat.log tool list -s session.json
```
