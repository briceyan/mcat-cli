# Integration Tests

Live integration tests are opt-in and call real MCP servers.

Endpoints are hardcoded in the test module:

- GitHub: `https://api.githubcopilot.com/mcp/`
- Figma: `https://mcp.figma.com/mcp`
- Linear: `https://mcp.linear.app/mcp`

## Flags

- `MCAT_IT=1`: enable live integration tests
- `MCAT_IT_INTERACTIVE_AUTH=1`: enable interactive no-wait auth completion tests
- `MCAT_IT_WAIT_TIMEOUT=<seconds>`: timeout for interactive continue step (default `420`)

## Run (easy)

Run non-interactive coverage:

```bash
MCAT_IT=1 uv run python -m unittest tests.integration.test_live_mcp_servers -v
```

This covers no-wait `auth start` for:
- GitHub (default client mode)
- Figma (provided `--client-name mcat-cli-it`)
- Linear (default client mode)

Run interactive no-wait completion tests (`auth start` + `auth continue`) for GitHub/Figma/Linear:

```bash
MCAT_IT=1 MCAT_IT_INTERACTIVE_AUTH=1 \
uv run python -m unittest tests.integration.test_live_mcp_servers -v
```

During interactive tests:
- each test prints an auth URL
- open the URL in browser and approve access
- test then completes via `auth continue`

## Notes

- Some environments/providers can reject startup (for example dynamic registration restrictions).
- Known provider-specific startup restrictions are skipped with explicit messages.
- These tests may be slower/flakier than unit tests due to network/provider behavior.
