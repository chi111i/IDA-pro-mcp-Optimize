"""Tests for cache.py — In-memory LRU response cache with TTL."""

import threading
import time

import pytest

from ida_pro_mcp.cache import ResponseCache


class TestStore:
    def test_returns_16_char_hex_id(self, response_cache):
        """Store returns a 16-character hex string."""
        cache_id = response_cache.store("hello")
        assert len(cache_id) == 16
        int(cache_id, 16)  # should not raise

    def test_unique_ids(self, response_cache):
        """Each store call returns a unique ID."""
        ids = {response_cache.store(f"data{i}") for i in range(10)}
        assert len(ids) == 10

    def test_stores_tool_name(self, response_cache):
        """Tool name is associated with cache entry."""
        cid = response_cache.store("data", tool_name="test_tool")
        result = response_cache.get(cid)
        assert result["tool_name"] == "test_tool"

    def test_stores_instance_id(self, response_cache):
        """Instance ID is associated with cache entry."""
        cid = response_cache.store("data", instance_id="abc1")
        result = response_cache.get(cid)
        assert result["instance_id"] == "abc1"


class TestGet:
    def test_full_content(self, response_cache):
        """Get with size=0 returns all content."""
        cid = response_cache.store("abcdefghij")
        result = response_cache.get(cid, offset=0, size=0)
        assert result["chunk"] == "abcdefghij"
        assert result["total_chars"] == 10
        assert result["remaining_chars"] == 0

    def test_offset_and_size(self, response_cache):
        """Get with offset/size returns correct slice."""
        cid = response_cache.store("abcdefghij")
        result = response_cache.get(cid, offset=3, size=4)
        assert result["chunk"] == "defg"
        assert result["offset"] == 3
        assert result["size"] == 4
        assert result["remaining_chars"] == 3  # hij

    def test_offset_beyond_content(self, response_cache):
        """Offset beyond content returns empty chunk."""
        cid = response_cache.store("abc")
        result = response_cache.get(cid, offset=999, size=10)
        assert result["chunk"] == ""
        assert result["size"] == 0

    def test_negative_offset_clamped(self, response_cache):
        """Negative offset is clamped to 0."""
        cid = response_cache.store("abc")
        result = response_cache.get(cid, offset=-5, size=0)
        assert result["offset"] == 0
        assert result["chunk"] == "abc"

    def test_size_exceeding_remaining(self, response_cache):
        """Size larger than remaining content is clamped."""
        cid = response_cache.store("abcde")
        result = response_cache.get(cid, offset=3, size=100)
        assert result["chunk"] == "de"
        assert result["size"] == 2
        assert result["remaining_chars"] == 0

    def test_nonexistent_raises_key_error(self, response_cache):
        """Get on non-existent ID raises KeyError."""
        with pytest.raises(KeyError):
            response_cache.get("nonexistent_id_")


class TestTTLExpiration:
    def test_expired_entry_raises(self):
        """Expired entry raises KeyError on get."""
        cache = ResponseCache(max_entries=10, ttl_seconds=0)
        cid = cache.store("will expire")
        time.sleep(0.01)
        with pytest.raises(KeyError):
            cache.get(cid)

    def test_not_expired_within_ttl(self):
        """Entry within TTL is still accessible."""
        cache = ResponseCache(max_entries=10, ttl_seconds=60)
        cid = cache.store("still valid")
        result = cache.get(cid)
        assert result["chunk"] == "still valid"


class TestLRUEviction:
    def test_evicts_at_capacity(self):
        """Oldest entry is evicted when capacity is exceeded."""
        cache = ResponseCache(max_entries=3, ttl_seconds=600)
        ids = [cache.store(f"item{i}") for i in range(4)]
        # First item should be evicted
        with pytest.raises(KeyError):
            cache.get(ids[0])
        # Last item should still exist
        result = cache.get(ids[3])
        assert result["chunk"] == "item3"

    def test_access_refreshes_lru_order(self):
        """Accessing an entry refreshes its LRU position."""
        cache = ResponseCache(max_entries=3, ttl_seconds=600)
        id0 = cache.store("item0")
        id1 = cache.store("item1")
        id2 = cache.store("item2")
        # Access item0 to refresh it
        cache.get(id0)
        # Add item3 -> should evict item1 (oldest untouched)
        cache.store("item3")
        assert cache.exists(id0)
        with pytest.raises(KeyError):
            cache.get(id1)


class TestDelete:
    def test_delete_existing(self, response_cache):
        """Delete returns True and removes entry."""
        cid = response_cache.store("x")
        assert response_cache.delete(cid) is True
        assert response_cache.exists(cid) is False

    def test_delete_nonexistent(self, response_cache):
        """Delete returns False for non-existent entry."""
        assert response_cache.delete("nonexistent") is False


class TestClear:
    def test_clear_returns_count(self, response_cache):
        """Clear returns the count of cleared entries."""
        response_cache.store("a")
        response_cache.store("b")
        response_cache.store("c")
        assert response_cache.clear() == 3
        assert response_cache.clear() == 0


class TestStats:
    def test_reports_correct_values(self, response_cache):
        """Stats reflect actual cache state."""
        response_cache.store("a")
        response_cache.store("b")
        stats = response_cache.stats()
        assert stats["entry_count"] == 2
        assert stats["max_entries"] == 5
        assert stats["ttl_seconds"] == 2


class TestExists:
    def test_exists_true(self, response_cache):
        """exists() returns True for stored entry."""
        cid = response_cache.store("hello")
        assert response_cache.exists(cid) is True

    def test_exists_false(self, response_cache):
        """exists() returns False for non-existent entry."""
        assert response_cache.exists("fake_id") is False


class TestConcurrency:
    def test_concurrent_store_get(self):
        """Concurrent store and get operations do not corrupt state."""
        cache = ResponseCache(max_entries=100, ttl_seconds=60)
        barrier = threading.Barrier(10)
        errors = []
        results = [None] * 10

        def worker(idx):
            try:
                barrier.wait(timeout=5)
                cid = cache.store(f"data-{idx}")
                result = cache.get(cid)
                results[idx] = result["chunk"]
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Errors in threads: {errors}"
        for i in range(10):
            assert results[i] == f"data-{i}"
