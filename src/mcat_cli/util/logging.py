from __future__ import annotations

import logging
from typing import Mapping

LOG_DOMAIN_TO_LOGGER = {
    "app": "mcat.app",
    "auth": "mcat.auth",
    "bridge": "mcat.bridge",
    "mcp": "mcat.mcp",
}
LOG_DOMAIN_ALIASES = {
    "proxy": "bridge",
}
DEFAULT_VERBOSE_DOMAINS = ("app", "auth", "bridge", "mcp")

LOG_LEVELS = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "warn": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}


def parse_log_level(value: str) -> int:
    level = LOG_LEVELS.get(value.lower())
    if level is None:
        allowed = ", ".join(sorted(LOG_LEVELS))
        raise ValueError(f"invalid log level '{value}' (expected one of: {allowed})")
    return level


def normalize_log_domain(value: str) -> str:
    domain = value.lower()
    domain = LOG_DOMAIN_ALIASES.get(domain, domain)
    if domain not in LOG_DOMAIN_TO_LOGGER:
        allowed = ", ".join(
            sorted((*LOG_DOMAIN_TO_LOGGER.keys(), *LOG_DOMAIN_ALIASES.keys()))
        )
        raise ValueError(
            f"invalid log domain '{value}' (expected one of: {allowed})"
        )
    return domain


def parse_log_specs(specs: list[str]) -> dict[str, int]:
    enabled: dict[str, int] = {}
    for spec in _iter_log_specs(specs):
        domain, sep, level_name = spec.partition(":")
        normalized = normalize_log_domain(domain)
        enabled[normalized] = parse_log_level(level_name) if sep else logging.INFO
    return enabled


def _iter_log_specs(specs: list[str]) -> list[str]:
    items: list[str] = []
    for raw in specs:
        for part in raw.split(","):
            spec = part.strip()
            if spec:
                items.append(spec)
    return items


def level_from_verbosity(verbosity: int) -> int | None:
    if verbosity <= 0:
        return None
    if verbosity == 1:
        return logging.INFO
    return logging.DEBUG


def resolve_enabled_logs(
    *,
    verbosity: int,
    specs: list[str] | None,
) -> dict[str, int]:
    enabled: dict[str, int] = {}
    base_level = level_from_verbosity(verbosity)
    if base_level is not None:
        enabled.update({domain: base_level for domain in DEFAULT_VERBOSE_DOMAINS})
    enabled.update(parse_log_specs(specs or []))
    return enabled


def configure_logging(
    *, enabled: Mapping[str, int], log_stderr: bool, log_file: str | None
) -> None:
    # Reset only our domain loggers so repeated invocations in-process don't duplicate handlers.
    for logger_name in set(LOG_DOMAIN_TO_LOGGER.values()):
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()
        logger.propagate = False
        logger.setLevel(logging.CRITICAL + 1)

    if not enabled:
        return

    if not log_stderr and not log_file:
        log_stderr = True

    formatter = logging.Formatter(
        fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    handlers: list[logging.Handler] = []

    if log_stderr:
        stderr_handler = logging.StreamHandler()
        stderr_handler.setFormatter(formatter)
        handlers.append(stderr_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    for domain, level in enabled.items():
        logger = logging.getLogger(LOG_DOMAIN_TO_LOGGER[normalize_log_domain(domain)])
        logger.setLevel(level)
        for handler in handlers:
            logger.addHandler(handler)
