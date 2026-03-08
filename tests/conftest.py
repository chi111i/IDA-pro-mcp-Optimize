"""Shared fixtures for IDA Pro MCP test suite."""

import sys
from pathlib import Path

# Ensure src/ is importable for all tests
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import pytest

from ida_pro_mcp.registry import InstanceRegistry
from ida_pro_mcp.cache import ResponseCache


@pytest.fixture
def tmp_registry(tmp_path):
    """InstanceRegistry backed by a temporary file."""
    registry_path = str(tmp_path / "instances.json")
    return InstanceRegistry(registry_path)


@pytest.fixture
def populated_registry(tmp_registry):
    """Registry pre-loaded with 3 instances."""
    tmp_registry.register(
        pid=100, port=5000, idb_path="/tmp/a.i64",
        binary_name="a.exe", host="127.0.0.1",
    )
    tmp_registry.register(
        pid=200, port=5001, idb_path="/tmp/b.i64",
        binary_name="b.exe", host="127.0.0.1",
    )
    tmp_registry.register(
        pid=300, port=5002, idb_path="/tmp/c.i64",
        binary_name="c.exe", host="127.0.0.1",
    )
    return tmp_registry


@pytest.fixture
def response_cache():
    """ResponseCache with small capacity and short TTL for testing."""
    return ResponseCache(max_entries=5, ttl_seconds=2)
