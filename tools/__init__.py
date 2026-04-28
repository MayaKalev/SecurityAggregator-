"""MCP-style tool registry."""

from .mcp_tools import (
    TOOLS,
    TOOL_DISPATCH,
    fetch_security_data,
    send_critical_alert,
    store_findings,
)

__all__ = [
    "TOOLS",
    "TOOL_DISPATCH",
    "fetch_security_data",
    "send_critical_alert",
    "store_findings",
]
