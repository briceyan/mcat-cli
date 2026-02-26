from __future__ import annotations

import logging
from typing import Mapping

LOG_DOMAINS = {
    "app": "mcat.app",
    "auth": "mcat.auth",
    "mcp": "mcat.mcp",
}

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


def parse_log_specs(specs: list[str]) -> dict[str, int]:
    enabled: dict[str, int] = {}
    for spec in specs:
        domain, sep, level_name = spec.partition(":")
        if domain not in LOG_DOMAINS:
            allowed = ", ".join(LOG_DOMAINS)
            raise ValueError(
                f"invalid log domain '{domain}' (expected one of: {allowed})"
            )
        enabled[domain] = parse_log_level(level_name) if sep else logging.INFO
    return enabled


def configure_logging(
    *, enabled: Mapping[str, int], log_stderr: bool, log_file: str | None
) -> None:
    # Reset only our domain loggers so repeated invocations in-process don't duplicate handlers.
    for logger_name in LOG_DOMAINS.values():
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
        logger = logging.getLogger(LOG_DOMAINS[domain])
        logger.setLevel(level)
        for handler in handlers:
            logger.addHandler(handler)
