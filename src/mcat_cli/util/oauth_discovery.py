from __future__ import annotations

from urllib import parse as urlparse


def build_protected_resource_metadata_urls(
    endpoint: str, *, hinted_resource_metadata: str | None = None
) -> list[str]:
    candidates: list[str] = []

    hinted = hinted_resource_metadata.strip() if hinted_resource_metadata else ""
    if hinted:
        candidates.append(hinted)

    parsed = urlparse.urlsplit(endpoint)
    if not parsed.scheme or not parsed.netloc:
        return _dedupe(candidates)

    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.strip("/")
    if path:
        candidates.append(f"{base}/.well-known/oauth-protected-resource/{path}")
    candidates.append(f"{base}/.well-known/oauth-protected-resource")
    return _dedupe(candidates)


def build_issuer_candidates(
    endpoint: str,
    *,
    discovered_authorization_servers: list[str],
    hinted_issuer: str | None,
) -> list[str]:
    candidates: list[str] = []
    candidates.extend(
        issuer
        for issuer in discovered_authorization_servers
        if isinstance(issuer, str) and issuer.strip()
    )

    hinted = hinted_issuer.strip() if hinted_issuer else ""
    if hinted:
        candidates.append(hinted)

    host_issuer = _mcp_host_issuer(endpoint)
    if not candidates:
        candidates.append(endpoint)
    if host_issuer:
        candidates.append(host_issuer)

    return _dedupe(candidates)


def build_authorization_server_metadata_urls(issuer: str) -> list[str]:
    issuer = issuer.rstrip("/")
    parsed = urlparse.urlsplit(issuer)
    if not parsed.scheme or not parsed.netloc:
        return []

    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.strip("/")
    urls: list[str] = []
    if path:
        urls.append(f"{base}/.well-known/oauth-authorization-server/{path}")
        urls.append(f"{base}/.well-known/openid-configuration/{path}")
        urls.append(f"{issuer}/.well-known/oauth-authorization-server")
        urls.append(f"{issuer}/.well-known/openid-configuration")
    else:
        urls.append(f"{issuer}/.well-known/oauth-authorization-server")
        urls.append(f"{issuer}/.well-known/openid-configuration")
    # Some servers expose metadata directly at the issuer URL.
    urls.append(issuer)
    return _dedupe(urls)


def _mcp_host_issuer(endpoint: str) -> str | None:
    parsed = urlparse.urlsplit(endpoint)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out
