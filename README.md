# mcat-cli

The model-context access tool for agents and humans.

`mcat` works with MCP servers through two file types:

- connection file: pre-init connection state (`-c, --connection`)
- session file: initialized MCP session state (`-s, --session`)

## Install

```bash
pip install mcat-cli
```

```bash
uv tool install mcat-cli
```

Requires Python 3.11+.

## Command Summary

- `bridge start|stop|status`: bridge a local stdio MCP server to HTTP
- `auth`: start or resume HTTP OAuth authorization
- `init`: initialize an MCP session from a connection file
- `tool` / `resource` / `prompt`: use server capabilities through a session file

## Typical Flows

### HTTP + Human

Authorize and block until the browser flow finishes:

```bash
mcat auth https://mcp.example.com/mcp \
  -c prod.connection.json \
  -k prod.token.json \
  --complete
```

Initialize a session:

```bash
mcat init -c prod.connection.json -s prod.session.json
```

Use the session:

```bash
mcat tool list -s prod.session.json
mcat resource list -s prod.session.json
mcat prompt list -s prod.session.json
```

### HTTP + Agent

Create or resume the connection without blocking:

```bash
mcat auth https://mcp.example.com/mcp \
  -c prod.connection.json \
  -k prod.token.json
```

The command returns JSON with `result.action.url`. Send that URL to the user.

After the browser step finishes, complete the stored flow:

```bash
mcat auth -c prod.connection.json --complete
```

Then initialize:

```bash
mcat init -c prod.connection.json -s prod.session.json
```

### HTTP + Container / Callback Proxy

If the browser cannot reach the loopback callback listener directly, provide:

- `--callback URL`: the public callback URL used in the OAuth authorization request
- `--listen ADDR`: where `mcat` listens locally for the forwarded callback (`PORT` or `HOST:PORT`)

Example:

```bash
mcat auth https://mcp.example.com/mcp \
  -c prod.connection.json \
  -k prod.token.json \
  --callback https://auth-proxy.example.com/callback \
  --listen 0.0.0.0:43123
```

The callback bridge should forward the raw callback query string to the local listener started by `mcat`.

### STDIO + Human or Agent

Start a local stdio-to-HTTP bridge and record it in a connection file:

```bash
mcat bridge start -c local.connection.json -- codex mcp-server
```

Or pin the local HTTP port:

```bash
mcat bridge start -c local.connection.json --port 6010 -- codex mcp-server
```

Initialize and use the session:

```bash
mcat init -c local.connection.json -s local.session.json
mcat tool list -s local.session.json
```

Stop the bridge:

```bash
mcat bridge stop -c local.connection.json
```

## Connection Files

Connection files are explicit JSON/JSON5 state shared across commands.

For HTTP connections they store:

- endpoint
- key reference
- current OAuth flow state
- callback/listener details when needed

For stdio connections they store:

- local bridge endpoint
- bridge process details

`init` reads the connection file so you do not need to repeat endpoint or token settings after `auth` or `bridge start`.

## Sessions

`init` writes a session file:

```bash
mcat init -c prod.connection.json -s prod.session.json
```

All capability commands reuse that same file:

```bash
mcat tool call TOOL_NAME -i '{"key":"value"}' -s prod.session.json
mcat resource read RESOURCE_URI -s prod.session.json
mcat prompt get PROMPT_NAME -s prod.session.json -i '{"arg":"value"}'
```

## Tokens and Secrets

Tokens and secrets can be specified with `-k, --key-ref` using:

- `env://VAR`
- `.env://path:VAR`
- `.env://:VAR`
- `json://path`
- `path` (same as `json://path`)

Notes:

- `auth` writes the token back to `--key-ref`
- existing destinations need `-o, --overwrite`
- `env://` is read-only for writes

## OAuth Client Information

Use client config when a provider expects a specific OAuth client.

`auth` supports:

- `--client CLIENT_INFO_FILE`
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

When `auth` is pending, the result includes the browser action URL and the connection file path.

Resource output modes:

- `mcat resource read ... -s session.json`: JSON result
- `mcat resource read ... -s session.json -o file.bin`: save decoded content to file + JSON metadata
- `mcat resource read ... -s session.json -o -`: write decoded bytes to stdout

When logging is enabled, logs go to stderr by default. If you pass `--log-output`, logs go to that file instead.

## Logging

`-v` sets the default log level for standard modules. `--log` overrides specific modules.

Use `-v` for info logs and `-vv` for debug logs:

```bash
mcat -v auth ...
```

Write logs to a file instead:

```bash
mcat -v --log-output mcat.log auth ...
```

Override specific module levels when needed:

```bash
mcat -v --log auth:debug,mcp:debug auth ...
```

Logging options are global and must be placed before the command name.
