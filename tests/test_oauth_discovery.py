from __future__ import annotations

import unittest

from mcat_cli.util.oauth_discovery import (
    build_authorization_server_metadata_urls,
    build_issuer_candidates,
    build_protected_resource_metadata_urls,
)


class OAuthDiscoveryCandidatesTest(unittest.TestCase):
    def test_build_protected_resource_metadata_urls_with_path(self) -> None:
        endpoint = "https://mcp.linear.app/mcp"

        self.assertEqual(
            build_protected_resource_metadata_urls(endpoint),
            [
                "https://mcp.linear.app/.well-known/oauth-protected-resource/mcp",
                "https://mcp.linear.app/.well-known/oauth-protected-resource",
            ],
        )

    def test_build_protected_resource_metadata_urls_with_hint(self) -> None:
        endpoint = "https://mcp.linear.app/mcp"
        hinted = "https://hinted.example/.well-known/oauth-protected-resource"

        self.assertEqual(
            build_protected_resource_metadata_urls(
                endpoint,
                hinted_resource_metadata=hinted,
            ),
            [
                hinted,
                "https://mcp.linear.app/.well-known/oauth-protected-resource/mcp",
                "https://mcp.linear.app/.well-known/oauth-protected-resource",
            ],
        )

    def test_build_authorization_server_metadata_urls_with_path(self) -> None:
        issuer = "https://api.figma.com/v1/oauth"

        self.assertEqual(
            build_authorization_server_metadata_urls(issuer),
            [
                "https://api.figma.com/.well-known/oauth-authorization-server/v1/oauth",
                "https://api.figma.com/.well-known/openid-configuration/v1/oauth",
                "https://api.figma.com/v1/oauth/.well-known/oauth-authorization-server",
                "https://api.figma.com/v1/oauth/.well-known/openid-configuration",
                "https://api.figma.com/v1/oauth",
            ],
        )

    def test_build_authorization_server_metadata_urls_no_path(self) -> None:
        issuer = "https://mcp.linear.app"

        self.assertEqual(
            build_authorization_server_metadata_urls(issuer),
            [
                "https://mcp.linear.app/.well-known/oauth-authorization-server",
                "https://mcp.linear.app/.well-known/openid-configuration",
                "https://mcp.linear.app",
            ],
        )

    def test_build_issuer_candidates_fallback(self) -> None:
        endpoint = "https://mcp.linear.app/mcp"

        self.assertEqual(
            build_issuer_candidates(
                endpoint,
                discovered_authorization_servers=[],
                hinted_issuer=None,
            ),
            [
                "https://mcp.linear.app/mcp",
                "https://mcp.linear.app",
            ],
        )

    def test_build_issuer_candidates_prefers_discovery_then_hint(self) -> None:
        endpoint = "https://mcp.linear.app/mcp"

        self.assertEqual(
            build_issuer_candidates(
                endpoint,
                discovered_authorization_servers=[
                    "https://issuer-a.example",
                    "https://issuer-b.example",
                ],
                hinted_issuer="https://hinted.example",
            ),
            [
                "https://issuer-a.example",
                "https://issuer-b.example",
                "https://hinted.example",
                "https://mcp.linear.app",
            ],
        )


if __name__ == "__main__":
    unittest.main()
