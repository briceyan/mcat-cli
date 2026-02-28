# Integration Tests

These tests exercise live MCP servers and are opt-in.

By default, normal test runs do not execute live integration tests.

## Prerequisites

- network access to target MCP servers
- credentials for any provider that requires them
- Python environment with project dependencies installed

## Environment flags

- `MCAT_IT=1`: enable live integration test module
- `MCAT_IT_INTERACTIVE_AUTH=1`: enable interactive auth completion tests
- `MCAT_IT_WAIT_TIMEOUT=<seconds>`: timeout for interactive waits (default `360`)

Provider configuration:

- `MCAT_IT_GH_PAT`: GitHub PAT used via `.env://:GH_PAT` key ref
- `MCAT_IT_GITHUB_ENDPOINT` (optional, default `https://api.githubcopilot.com/mcp/`)
- `MCAT_IT_FIGMA_ENDPOINT` (optional, default `https://mcp.figma.com/mcp`)
- `MCAT_IT_FIGMA_CLIENT_NAME` (optional, default `mcat-cli-it`)
- `MCAT_IT_LINEAR_ENDPOINT` (optional, default `https://mcp.linear.app/mcp`)

## Run commands

Run only integration module:

```bash
MCAT_IT=1 uv run python -m unittest tests.integration.test_live_mcp_servers -v
```

Run GitHub flow (non-interactive):

```bash
MCAT_IT=1 \
MCAT_IT_GH_PAT='ghp_xxx' \
MCAT_IT_GITHUB_ENDPOINT='https://api.githubcopilot.com/mcp/' \
uv run python -m unittest tests.integration.test_live_mcp_servers.LiveMcpServersTest.test_github_env_key_ref_init_and_tool_list -v
```

Run Linear/Figma non-wait auth start coverage:

```bash
MCAT_IT=1 \
MCAT_IT_LINEAR_ENDPOINT='https://mcp.linear.app/mcp' \
MCAT_IT_FIGMA_ENDPOINT='https://mcp.figma.com/mcp' \
MCAT_IT_FIGMA_CLIENT_NAME='mcat-cli-it' \
uv run python -m unittest tests.integration.test_live_mcp_servers -v
```

Run interactive auth completion tests (`--wait` and no-`--wait` + `continue`):

```bash
MCAT_IT=1 \
MCAT_IT_INTERACTIVE_AUTH=1 \
MCAT_IT_LINEAR_ENDPOINT='https://mcp.linear.app/mcp' \
uv run python -m unittest tests.integration.test_live_mcp_servers.LiveMcpServersTest.test_linear_auth_start_wait_completes -v
```

```bash
MCAT_IT=1 \
MCAT_IT_INTERACTIVE_AUTH=1 \
MCAT_IT_LINEAR_ENDPOINT='https://mcp.linear.app/mcp' \
uv run python -m unittest tests.integration.test_live_mcp_servers.LiveMcpServersTest.test_linear_auth_no_wait_then_continue_completes -v
```

## Notes

- Interactive tests require browser approval while the test is running.
- Tests skip automatically when required flags/secrets are missing.
- These tests call real external services and may be slower/flakier than unit tests.
