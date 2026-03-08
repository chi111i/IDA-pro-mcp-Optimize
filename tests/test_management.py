"""Tests for tools/management.py — Multi-instance management tools."""

import os
import time

import pytest

from ida_pro_mcp.registry import InstanceRegistry
from ida_pro_mcp.cache import ResponseCache, get_cache
from ida_pro_mcp.tools.management import (
    list_instances,
    get_cached_output,
    refresh_instances,
)


class TestListInstances:
    def test_empty_registry(self, tmp_path):
        """Empty registry returns count=0."""
        reg = InstanceRegistry(str(tmp_path / "empty.json"))
        result = list_instances(reg)
        assert result["count"] == 0
        assert result["instances"] == []

    def test_populated_registry(self, populated_registry):
        """Populated registry returns correct count and metadata."""
        result = list_instances(populated_registry)
        assert result["count"] == 3
        assert len(result["instances"]) == 3

        # Verify each instance has required fields
        for inst in result["instances"]:
            assert "instance_id" in inst
            assert "binary_name" in inst
            assert "host" in inst
            assert "port" in inst
            assert "pid" in inst

    def test_includes_active_instance(self, populated_registry):
        """Result includes active_instance field."""
        result = list_instances(populated_registry)
        assert "active_instance" in result
        assert result["active_instance"] is not None


class TestGetCachedOutput:
    def test_retrieve_cached_content(self):
        """Retrieves cached content by ID."""
        cache = get_cache()
        cid = cache.store("hello world", tool_name="test")
        result = get_cached_output(cid)
        assert result["chunk"] == "hello world"
        assert result["total_chars"] == 11
        # Clean up
        cache.delete(cid)

    def test_retrieve_with_offset(self):
        """Retrieves cached content with offset/size pagination."""
        cache = get_cache()
        cid = cache.store("abcdefghij", tool_name="test")
        result = get_cached_output(cid, offset=3, size=4)
        assert result["chunk"] == "defg"
        assert result["remaining_chars"] == 3
        cache.delete(cid)

    def test_nonexistent_cache_id(self):
        """Non-existent cache ID returns error dict."""
        result = get_cached_output("nonexistent_id__")
        assert "error" in result
        assert "not found" in result["error"]


class TestRefreshInstances:
    def test_removes_dead_instances(self, tmp_path):
        """Refresh removes instances with dead PIDs."""
        reg = InstanceRegistry(str(tmp_path / "refresh.json"))
        reg.register(
            pid=2**30,  # non-existent PID
            port=5000, idb_path="/test.i64",
            binary_name="test.exe", host="127.0.0.1",
        )
        result = refresh_instances(reg)
        assert result["removed_count"] >= 1
        assert result["total_count"] == 0

    def test_keeps_alive_instances(self, tmp_path):
        """Refresh keeps alive instances."""
        reg = InstanceRegistry(str(tmp_path / "alive.json"))
        reg.register(
            pid=os.getpid(),  # our own PID is alive
            port=5000, idb_path="/test.i64",
            binary_name="test.exe", host="127.0.0.1",
        )
        result = refresh_instances(reg)
        assert result["total_count"] == 1

    def test_result_structure(self, tmp_path):
        """Result has all expected fields."""
        reg = InstanceRegistry(str(tmp_path / "struct.json"))
        result = refresh_instances(reg)
        assert "removed" in result
        assert "removed_count" in result
        assert "discovered" in result
        assert "discovered_count" in result
        assert "instances" in result
        assert "total_count" in result
