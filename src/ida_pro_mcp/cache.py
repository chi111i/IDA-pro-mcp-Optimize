"""Response cache for large IDA tool outputs.

Provides in-memory LRU caching with TTL for tool responses that exceed
the default output limit, enabling pagination via offset/size.

Adapted from ida-multi-mcp project.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

# Configuration
DEFAULT_MAX_OUTPUT_CHARS = 50000  # Default truncation limit (match mcp-plugin.py)
CACHE_MAX_ENTRIES = 200           # Maximum cached responses
CACHE_TTL_SECONDS = 600           # 10 minutes


@dataclass
class CacheEntry:
    """A cached response entry."""

    content: str
    created_at: float
    tool_name: str
    instance_id: str | None


class ResponseCache:
    """In-memory LRU cache for large IDA tool responses.

    When a tool response exceeds the output limit, the full content is
    stored here and clients retrieve it in chunks via ``get()``.

    Thread-safe: all public methods acquire the internal lock.
    """

    def __init__(
        self,
        max_entries: int = CACHE_MAX_ENTRIES,
        ttl_seconds: int = CACHE_TTL_SECONDS,
    ) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(
        self,
        content: str,
        tool_name: str = "",
        instance_id: str | None = None,
    ) -> str:
        """Store content and return a 16-char hex cache ID.

        Args:
            content: Full response content to cache.
            tool_name: Name of the tool that produced the response.
            instance_id: IDA instance ID (if applicable).

        Returns:
            16-character hex cache ID for later retrieval.
        """
        with self._lock:
            self._evict_expired()

            # Evict oldest (LRU) if at capacity
            while len(self._cache) >= self.max_entries:
                self._cache.popitem(last=False)

            # 16-char hex ID prevents brute-force enumeration
            cache_id = uuid.uuid4().hex[:16]

            self._cache[cache_id] = CacheEntry(
                content=content,
                created_at=time.time(),
                tool_name=tool_name,
                instance_id=instance_id,
            )
            self._cache.move_to_end(cache_id)
            return cache_id

    def get(
        self,
        cache_id: str,
        offset: int = 0,
        size: int = DEFAULT_MAX_OUTPUT_CHARS,
    ) -> dict[str, Any]:
        """Retrieve cached content by offset and size (pagination).

        Args:
            cache_id: The cache identifier returned by ``store()``.
            offset: Starting character position (0-indexed).
            size: Number of characters to return (0 = all remaining).

        Returns:
            Dict with keys: ``chunk``, ``offset``, ``size``,
            ``total_chars``, ``remaining_chars``, ``cache_id``,
            ``tool_name``, ``instance_id``.

        Raises:
            KeyError: If *cache_id* not found or expired.
        """
        with self._lock:
            self._evict_expired()

            if cache_id not in self._cache:
                raise KeyError(f"Cache entry '{cache_id}' not found or expired")

            entry = self._cache[cache_id]
            self._cache.move_to_end(cache_id)  # LRU touch

            total_chars = len(entry.content)

            if offset < 0:
                offset = 0
            if offset >= total_chars:
                return {
                    "chunk": "",
                    "offset": offset,
                    "size": 0,
                    "total_chars": total_chars,
                    "remaining_chars": 0,
                    "cache_id": cache_id,
                    "tool_name": entry.tool_name,
                    "instance_id": entry.instance_id,
                }

            actual_size = (total_chars - offset) if size <= 0 else min(size, total_chars - offset)
            chunk = entry.content[offset : offset + actual_size]
            remaining = total_chars - offset - actual_size

            return {
                "chunk": chunk,
                "offset": offset,
                "size": actual_size,
                "total_chars": total_chars,
                "remaining_chars": remaining,
                "cache_id": cache_id,
                "tool_name": entry.tool_name,
                "instance_id": entry.instance_id,
            }

    def exists(self, cache_id: str) -> bool:
        """Check if a cache entry exists and is not expired."""
        with self._lock:
            self._evict_expired()
            return cache_id in self._cache

    def delete(self, cache_id: str) -> bool:
        """Delete a cache entry.  Returns True if it existed."""
        with self._lock:
            if cache_id in self._cache:
                del self._cache[cache_id]
                return True
            return False

    def clear(self) -> int:
        """Clear all entries.  Returns the count of cleared entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            self._evict_expired()
            return {
                "entry_count": len(self._cache),
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_expired(self) -> int:
        """Remove entries older than TTL.  Returns count evicted."""
        now = time.time()
        expired = [
            cid
            for cid, entry in self._cache.items()
            if now - entry.created_at > self.ttl_seconds
        ]
        for cid in expired:
            del self._cache[cid]
        return len(expired)


# ------------------------------------------------------------------
# Global singleton (thread-safe double-checked locking)
# ------------------------------------------------------------------

_response_cache: ResponseCache | None = None
_cache_init_lock = threading.Lock()


def get_cache() -> ResponseCache:
    """Get the global response cache singleton."""
    global _response_cache
    if _response_cache is None:
        with _cache_init_lock:
            if _response_cache is None:
                _response_cache = ResponseCache()
    return _response_cache
