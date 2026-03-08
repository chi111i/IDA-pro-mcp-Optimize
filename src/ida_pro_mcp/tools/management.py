"""Multi-instance management tools for the MCP server.

These tools are registered as local MCP tools (not forwarded to IDA)
and provide instance discovery, cache retrieval, and registry management.

Only active in multi-instance mode.
"""

from __future__ import annotations

import sys
from typing import Any, Optional

from ..cache import get_cache, DEFAULT_MAX_OUTPUT_CHARS
from ..health import cleanup_stale_instances, rediscover_instances
from ..registry import InstanceRegistry


def list_instances(registry: InstanceRegistry) -> dict[str, Any]:
    """List all registered IDA instances.

    Returns information about all active IDA Pro instances including
    their instance ID, binary name, architecture, host, port, and
    registration time.

    Returns:
        Dict with ``instances`` list and ``count``.
    """
    instances = registry.list_instances()
    result = []
    for iid, info in instances.items():
        result.append({
            "instance_id": iid,
            "binary_name": info.get("binary_name", "unknown"),
            "binary_path": info.get("binary_path", ""),
            "arch": info.get("arch", "unknown"),
            "host": info.get("host", "127.0.0.1"),
            "port": info.get("port"),
            "pid": info.get("pid"),
            "registered_at": info.get("registered_at", ""),
            "last_heartbeat": info.get("last_heartbeat", ""),
        })
    return {
        "instances": result,
        "count": len(result),
        "active_instance": registry.get_active(),
    }


def get_cached_output(
    cache_id: str,
    offset: int = 0,
    size: int = DEFAULT_MAX_OUTPUT_CHARS,
) -> dict[str, Any]:
    """Retrieve cached output from a previous tool call.

    When a tool response is too large, it is cached and a cache_id is
    returned. Use this tool to retrieve the full output in pages.

    Args:
        cache_id: The cache identifier from a truncated response.
        offset: Starting character position (0-indexed).
        size: Number of characters to return (0 = all remaining).

    Returns:
        Dict with ``chunk``, ``offset``, ``size``, ``total_chars``,
        ``remaining_chars``, and ``cache_id``.
    """
    cache = get_cache()
    try:
        return cache.get(cache_id, offset=offset, size=size)
    except KeyError:
        return {
            "error": f"Cache entry '{cache_id}' not found or expired.",
            "hint": "Cache entries expire after 10 minutes. "
                    "Re-run the original tool call to regenerate.",
        }


def refresh_instances(registry: InstanceRegistry) -> dict[str, Any]:
    """Refresh the instance registry.

    Performs three operations:
    1. Removes instances whose IDA process has died.
    2. Auto-discovers running IDA instances with MCP plugins.
    3. Returns the updated instance list.

    Returns:
        Dict with ``removed``, ``discovered``, and ``instances``.
    """
    # Clean up dead instances
    removed = cleanup_stale_instances(registry)

    # Auto-discover new instances
    discovered = rediscover_instances(registry)

    # Return updated state
    instances = registry.list_instances()
    return {
        "removed": removed,
        "removed_count": len(removed),
        "discovered": discovered,
        "discovered_count": len(discovered),
        "instances": [
            {"instance_id": iid, "binary_name": info.get("binary_name", "unknown")}
            for iid, info in instances.items()
        ],
        "total_count": len(instances),
    }
