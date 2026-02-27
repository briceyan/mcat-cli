# mcat-cli

The model-context access tool for agents and humans.

`mcat` is a concise CLI for:
- OAuth authorization against MCP servers
- MCP session initialization
- tool listing/calling
- resource listing/reading

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

4) Call MCP tools/resources:

```bash
mcat tool list -s session.json
mcat tool call my_tool -i '{"foo":"bar"}' -s session.json

mcat resource list -s session.json
mcat resource list-template -s session.json
mcat resource read my://resource -s session.json
```

## KEY_REF Formats

`-k/--key-ref` accepts:
- `env://VAR`
- `.env://path:VAR`
- `json://path`
- bare file path (same as `json://path`)

For auth flows, token output is written back to `--key-ref`.
- Missing destination is allowed (first-time auth).
- Existing destination requires `-o/--overwrite`.

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
