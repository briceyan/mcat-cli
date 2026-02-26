from __future__ import annotations

import logging
from typing import Any

LOGGER = logging.getLogger("mcat.mcp")


def init_session(*, endpoint: str, key_ref: str, sess_info_file: str) -> dict[str, Any]:
    LOGGER.info("mcp.init requested endpoint=%s", endpoint)
    _ = (key_ref, sess_info_file)
    raise NotImplementedError("session init is not implemented yet")


def list_tools(*, sess_info_file: str) -> dict[str, Any]:
    LOGGER.info("mcp.tool.list requested sess_info_file=%s", sess_info_file)
    raise NotImplementedError("tool listing is not implemented yet")


def call_tool(
    *, tool_name: str, args_input: str, sess_info_file: str
) -> dict[str, Any]:
    LOGGER.info("mcp.tool.call requested tool_name=%s", tool_name)
    _ = (args_input, sess_info_file)
    raise NotImplementedError("tool call is not implemented yet")
