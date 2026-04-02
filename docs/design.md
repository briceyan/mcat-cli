# mcat-cli Design

## Goals

`mcat-cli` is a compact MCP shell tool for both humans and agents.

Design priorities:

- agent-friendly JSON output
- human-friendly command sequences
- explicit file-based state
- small implementation surface
- support for both HTTP OAuth servers and local stdio servers

## Core Model

The CLI uses two explicit files:

- connection file: pre-init connection state
- session file: initialized MCP session state

This keeps the flow consistent:

1. prepare a connection
2. initialize a session
3. use tools/resources/prompts through the session

## Command Surface

```bash
mcat [GLOBAL_OPTS] auth [ENDPOINT] -c CONNECTION_FILE [-k KEY_REF] [--complete] [--callback URL] [--listen ADDR] [-o] [--client CLIENT_INFO_FILE] [--client-id CLIENT_ID] [--client-secret KEY_SPEC] [--client-name CLIENT_NAME]

mcat [GLOBAL_OPTS] bridge start -c CONNECTION_FILE [--port PORT] -- CMD [ARG...]
mcat [GLOBAL_OPTS] bridge stop -c CONNECTION_FILE
mcat [GLOBAL_OPTS] bridge status -c CONNECTION_FILE

mcat [GLOBAL_OPTS] init -c CONNECTION_FILE -s SESSION_INFO_FILE

mcat [GLOBAL_OPTS] resource list -s SESSION_INFO_FILE [--cursor CURSOR]
mcat [GLOBAL_OPTS] resource read URI -s SESSION_INFO_FILE [-o FILE]
mcat [GLOBAL_OPTS] resource list-template -s SESSION_INFO_FILE [--cursor CURSOR]

mcat [GLOBAL_OPTS] prompt list -s SESSION_INFO_FILE [--cursor CURSOR]
mcat [GLOBAL_OPTS] prompt get PROMPT_NAME -s SESSION_INFO_FILE [-i ARGS]

mcat [GLOBAL_OPTS] tool list -s SESSION_INFO_FILE
mcat [GLOBAL_OPTS] tool call TOOL_NAME -i ARGS -s SESSION_INFO_FILE
```

## Connection Preparation

### HTTP

`auth` is the only HTTP connection-preparation command.

- If the token in `KEY_REF` is already valid, `auth` records the connection and completes immediately.
- If OAuth is required, `auth` creates or resumes a pending authorization flow inside the connection file.
- Default behavior is non-blocking and returns a browser action URL.
- `--complete` blocks until the flow finishes and stores the token.

This keeps agent and human usage aligned:

- agents: `auth` then `auth --complete`
- humans: `auth --complete`

### STDIO

`bridge start` launches a local stdio-to-HTTP bridge and writes the resulting local HTTP endpoint into the connection file.

`bridge stop` and `bridge status` also operate through the same connection file.

This means `init` never needs to know whether the source was HTTP or stdio. It only reads the connection file.

## Callback Handling

Authorization-code flows may require a public callback URL that is different from the local listener.

The CLI exposes:

- `--callback URL`: the public callback URL placed into the authorization request
- `--listen ADDR`: the local callback listener address (`PORT` or `HOST:PORT`)

Rules:

- if `--callback` is omitted, the local listener redirect URI is used directly
- if `--listen` is omitted, the listener binds to loopback on a random port
- when `--callback` is used, an external proxy/tunnel may forward the raw callback query string to the local listener

This separates the user intent from the local network topology.

## Connection File Shape

Connection files are JSON/JSON5 objects. The schema is intentionally transport-oriented rather than auth-only.

Current shape:

```json
{
  "version": 2,
  "kind": "http",
  "endpoint": "https://example.com/mcp",
  "key_ref": "json://token.json",
  "flow": "authorization_code",
  "state": {},
  "bridge": {}
}
```

Meaning:

- `kind`: `http` or `stdio`
- `endpoint`: the endpoint that `init` will use
- `key_ref`: token/key location when applicable
- `flow`: auth flow name for HTTP OAuth, otherwise null
- `state`: transport-specific mutable state
- `bridge`: stdio bridge runtime details when applicable

For HTTP OAuth, `state` may include:

- `status`
- `authorization_url`
- `oauth_redirect_uri`
- `listen_uri`
- PKCE values and token endpoints

For stdio bridge connections, `bridge` may include:

- `pid`
- `port`
- `log_file`
- upstream command details

## Session File Shape

`init` writes a session file that captures the initialized MCP session:

```json
{
  "version": 1,
  "endpoint": "http://127.0.0.1:6010/mcp",
  "key_ref": null,
  "session_id": "abc",
  "session_mode": "stateful"
}
```

All follow-up capability commands consume this file.

## JSON Output

All command results go to stdout as JSON.

Success:

```json
{"ok":true}
```

Success with payload:

```json
{"ok":true,"result":{}}
```

Failure:

```json
{"ok":false,"error":"message"}
```

Pending auth result:

```json
{
  "ok": true,
  "result": {
    "status": "pending",
    "connection_file": "/path/to/conn.json",
    "action": {
      "url": "https://..."
    },
    "callback": {
      "public_url": "https://bridge.example.com/callback",
      "listen_url": "http://0.0.0.0:43123/callback"
    }
  }
}
```

Complete auth result:

```json
{
  "ok": true,
  "result": {
    "status": "complete",
    "stored": "json:///path/to/token.json",
    "connection_file": "/path/to/conn.json"
  }
}
```

## Concurrency

State is explicit and file-based:

- no shared global mutable state
- file writes use atomic replace
- mutable state files are lock-protected where needed

This supports interleaved agent runs and resumable flows.

## Logging

Log domains:

- `app`
- `auth`
- `bridge`
- `mcp`

Logs are disabled by default and go to stderr or a configured log file when enabled.

`-v` sets the default log level for standard modules. `--log` overrides specific modules.
