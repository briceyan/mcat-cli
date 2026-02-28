# mcat-cli

The model-context access tool for agents and humans.

`mcat` is a CLI to interact with MCP servers from an endpoint.

`mcat` provides:
- `auth start`: start authorization and return action details (URL/code)
- `auth continue`: resume a paused auth flow
- `init`: run MCP `initialize` and store session info
- `tool` / `resource` / `prompt`: access server capabilities

## Install

Example install commands:

```bash
pip install mcat-cli
```

```bash
uv tool install mcat-cli
```

Requires Python 3.11+.

## Typical Flow

1. Start auth (non-blocking):

```bash
mcat auth start https://mcp.example.com/mcp \
  -k token.json \
  --state auth.json
```

2. Continue auth after browser approval:

```bash
mcat auth continue --state auth.json -k token.json
```

3. Initialize MCP session:

```bash
mcat init https://mcp.example.com/mcp -k token.json -o session.json
```

4. Discover and use server utilities:

```bash
mcat tool list -s session.json
mcat tool call TOOL_NAME -i '{"key":"value"}' -s session.json

mcat resource list -s session.json
mcat resource read RESOURCE_URI -s session.json

mcat prompt list -s session.json
mcat prompt get PROMPT_NAME -s session.json -i '{"arg":"value"}'
```

If you are a human using the CLI directly, add `--wait` to `auth start`:

```bash
mcat auth start https://mcp.example.com/mcp -k token.json --state auth.json --wait
```

## Tokens and secrets

Tokens and secrets can be specified by `-k/--key-ref` and `KEY_SPEC` using these patterns:
- `env://VAR`
- `.env://path:VAR`
- `.env://:VAR` (same as `.env://.env:VAR`)
- `json://path`
- `path` (same as `json://path`)

Notes:
- auth writes token back to `--key-ref`
- existing destination needs `-o/--overwrite`
- `env://` is read-only for writes

Examples:
- Existing token/PAT in environment variable:

```bash
mcat init https://mcp.example.com/mcp -k env://MCP_TOKEN -o session.json
```

- Existing token/PAT in `.env` file:

```bash
mcat init https://mcp.example.com/mcp -k .env://.env:MCP_TOKEN -o session.json
```

For GitHub MCP usage, if you already have a GitHub PAT, you can reference it from `env://...` or `.env://...` directly.

## Provide OAuth Client Information

Use client config when a provider expects a specific OAuth client (for example, pre-registered client settings in services like Linear, or enterprise OAuth setups).

`auth start` supports:
- `-c/--client CLIENT_INFO_FILE`
- `--client-id ID`
- `--client-secret KEY_SPEC`
- `--client-name NAME`

Resolution order:
1. CLI overrides
2. `--client` file
3. built-in defaults

Modes:
- static client mode: resolved `client_id` present
- dynamic registration mode: no resolved `client_id`, uses resolved `client_name`

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
  "resource": "https://mcp.example.com/mcp"
}
```

## Output

Most commands emit JSON to stdout:

```json
{"ok":true,"result":{}}
```

```json
{"ok":false,"error":"message"}
```

Resource output modes:
- `mcat resource read ... -s session.json`: JSON result
- `mcat resource read ... -s session.json -o file.bin`: save decoded content to file + JSON metadata
- `mcat resource read ... -s session.json -o -`: write decoded bytes to stdout

When logging is enabled, log output is sent to stderr by default.

## Logging

If something goes wrong, enable logs for `auth`, `mcp`, and `app`:

```bash
mcat --log auth --log mcp --log app --log-stderr auth start ...
```

To include HTTP request/response bodies, use `:debug` level:

```bash
mcat --log auth:debug --log mcp:debug --log app:debug --log-stderr auth start ...
```

Logging options are global options and must be placed before the command name.
