"""End-to-end integration tests for the multi-instance IDA Pro MCP system.

Tests the full data flow: registration -> routing -> caching ->
management tools -> expiration/cleanup.
"""

import json
import os
import time
from unittest.mock import patch, MagicMock

import pytest

from ida_pro_mcp.registry import InstanceRegistry
from ida_pro_mcp.router import InstanceRouter
from ida_pro_mcp.cache import ResponseCache
from ida_pro_mcp.tools.management import (
    list_instances,
    get_cached_output,
    refresh_instances,
)
from ida_pro_mcp.health import cleanup_stale_instances
from ida_pro_mcp.tool_registry import (
    parse_plugin_file,
    generate_code,
    generate_tool_schemas,
)


PLUGIN_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "ida_pro_mcp", "mcp-plugin.py"
)


class TestFullMultiInstanceWorkflow:
    """Tests the complete lifecycle: register -> route -> expire -> cleanup."""

    def test_register_route_expire_cycle(self, tmp_path):
        """Full lifecycle: register two instances, route, expire one, verify."""
        reg = InstanceRegistry(str(tmp_path / "lifecycle.json"))

        # Step 1: Register two instances
        iid1 = reg.register(
            pid=os.getpid(), port=7000, idb_path="/bin/a.i64",
            binary_name="a.exe", host="127.0.0.1", arch="x64",
        )
        iid2 = reg.register(
            pid=os.getpid(), port=7001, idb_path="/bin/b.i64",
            binary_name="b.exe", host="127.0.0.1", arch="arm",
        )
        assert iid1 != iid2
        assert len(reg.list_instances()) == 2

        # Step 2: Router requires instance_id with multiple instances
        router = InstanceRouter(reg)
        resp = router.route_request("test_method", {"arguments": {}})
        assert "error" in resp
        assert "instance_id" in resp["error"]

        # Step 3: Route with explicit instance_id (mock HTTP)
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "result": {"functions": ["main", "init"]},
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "a.exe"}):
            with patch("http.client.HTTPConnection", return_value=mock_conn):
                resp = router.route_request("list_functions", {
                    "arguments": {"instance_id": iid1},
                })
        assert resp == {"functions": ["main", "init"]}

        # Step 4: Expire instance 1
        reg.expire_instance(iid1, reason="binary_changed", replaced_by=iid2)
        assert reg.get_instance(iid1) is None
        expired = reg.get_expired(iid1)
        assert expired is not None
        assert expired["reason"] == "binary_changed"
        assert expired["replaced_by"] == iid2

        # Step 5: Routing to expired instance returns helpful error
        resp = router.route_request("test", {
            "arguments": {"instance_id": iid1},
        })
        assert "error" in resp
        assert "expired" in resp["error"].lower() or "reason" in resp

        # Step 6: Single instance remaining -> auto-routing works
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "b.exe"}):
            with patch("http.client.HTTPConnection", return_value=mock_conn):
                resp = router.route_request("get_metadata", {
                    "arguments": {},
                })
        # Should auto-route to iid2 (the only remaining instance)
        assert "error" not in resp

    def test_management_tools_integration(self, tmp_path):
        """Management tools work with real registry operations."""
        reg = InstanceRegistry(str(tmp_path / "mgmt.json"))

        # Register instances
        iid1 = reg.register(
            pid=os.getpid(), port=7000, idb_path="/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        iid2 = reg.register(
            pid=os.getpid(), port=7001, idb_path="/b.i64",
            binary_name="b.exe", host="127.0.0.1",
        )

        # list_instances returns full info
        result = list_instances(reg)
        assert result["count"] == 2
        instance_ids = {i["instance_id"] for i in result["instances"]}
        assert iid1 in instance_ids
        assert iid2 in instance_ids

        # refresh_instances with alive PIDs keeps them
        result = refresh_instances(reg)
        assert result["total_count"] == 2
        assert result["removed_count"] == 0


class TestCacheAndPaginationFlow:
    """Tests the cache store -> paginated retrieval flow."""

    def test_store_and_paginate_large_output(self):
        """Large output is stored and retrieved in pages."""
        cache = ResponseCache(max_entries=10, ttl_seconds=60)
        large_content = "X" * 10000

        # Store
        cid = cache.store(large_content, tool_name="decompile_function")

        # Page 1
        page1 = cache.get(cid, offset=0, size=3000)
        assert len(page1["chunk"]) == 3000
        assert page1["total_chars"] == 10000
        assert page1["remaining_chars"] == 7000

        # Page 2
        page2 = cache.get(cid, offset=3000, size=3000)
        assert len(page2["chunk"]) == 3000
        assert page2["remaining_chars"] == 4000

        # Page 3
        page3 = cache.get(cid, offset=6000, size=3000)
        assert len(page3["chunk"]) == 3000
        assert page3["remaining_chars"] == 1000

        # Page 4 (last)
        page4 = cache.get(cid, offset=9000, size=3000)
        assert len(page4["chunk"]) == 1000
        assert page4["remaining_chars"] == 0

        # Reconstruct
        full = page1["chunk"] + page2["chunk"] + page3["chunk"] + page4["chunk"]
        assert full == large_content

    def test_management_cache_integration(self):
        """get_cached_output works with the global cache singleton."""
        from ida_pro_mcp.cache import get_cache

        cache = get_cache()
        content = "integration test data"
        cid = cache.store(content, tool_name="test_tool")

        result = get_cached_output(cid)
        assert result["chunk"] == content

        # Cleanup
        cache.delete(cid)


class TestToolRegistryIntegration:
    """Tests the AST parsing -> code generation -> schema pipeline."""

    def test_full_pipeline(self, tmp_path):
        """Parse -> generate code -> write file -> validate."""
        result = parse_plugin_file(PLUGIN_PATH)

        # Verify non-trivial parsing
        assert len(result.functions) > 50
        assert len(result.types) > 10

        # Generate code
        code = generate_code(result)
        assert len(code) > 1000

        # Write to temp file
        output_path = str(tmp_path / "server_generated.py")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(code)

        # Verify it's valid Python
        compile(code, output_path, "exec")

        # Generate schemas
        schemas = generate_tool_schemas(result)
        assert len(schemas) == len(result.functions)

        # Verify all schemas have instance_id parameter
        for schema in schemas:
            param_names = [p["name"] for p in schema["parameters"]]
            assert "instance_id" in param_names, (
                f"Schema for '{schema['name']}' missing instance_id"
            )


class TestRegistryResilience:
    """Tests registry behavior under adverse conditions."""

    def test_concurrent_register_unregister(self, tmp_path):
        """Concurrent register/unregister does not corrupt registry."""
        import threading

        reg = InstanceRegistry(str(tmp_path / "concurrent.json"))
        errors = []
        registered_ids = []
        lock = threading.Lock()

        def register_worker(idx):
            try:
                iid = reg.register(
                    pid=1000 + idx, port=5000 + idx,
                    idb_path=f"/tmp/{idx}.i64",
                    binary_name=f"bin{idx}.exe", host="127.0.0.1",
                )
                with lock:
                    registered_ids.append(iid)
            except Exception as e:
                with lock:
                    errors.append(e)

        # Register 10 instances concurrently
        threads = [
            threading.Thread(target=register_worker, args=(i,))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Errors during concurrent registration: {errors}"
        assert len(registered_ids) == 10

        # Verify all are in registry
        instances = reg.list_instances()
        assert len(instances) == 10

    def test_registry_recovery_after_corruption(self, tmp_path):
        """Registry recovers gracefully from corrupted state."""
        registry_path = str(tmp_path / "recovery.json")
        reg = InstanceRegistry(registry_path)

        # Register an instance
        iid = reg.register(
            pid=100, port=5000, idb_path="/test.i64",
            binary_name="test.exe", host="127.0.0.1",
        )
        assert reg.get_instance(iid) is not None

        # Corrupt the file
        with open(registry_path, "w") as f:
            f.write("CORRUPTED DATA!!!")

        # Next operation should recover
        instances = reg.list_instances()
        assert instances == {}  # Starts fresh

        # Can register again
        iid2 = reg.register(
            pid=200, port=5001, idb_path="/test2.i64",
            binary_name="test2.exe", host="127.0.0.1",
        )
        assert reg.get_instance(iid2) is not None


class TestSSRFProtectionEndToEnd:
    """Tests SSRF protection across the entire stack."""

    def test_registry_rejects_non_localhost(self, tmp_path):
        """Registry rejects non-localhost hosts."""
        reg = InstanceRegistry(str(tmp_path / "ssrf.json"))
        with pytest.raises(ValueError, match="Invalid host"):
            reg.register(
                pid=100, port=5000, idb_path="/test.i64",
                binary_name="test.exe", host="192.168.1.1",
            )

    def test_router_rejects_non_localhost(self, tmp_path):
        """Router rejects requests to non-localhost hosts."""
        reg = InstanceRegistry(str(tmp_path / "ssrf2.json"))
        router = InstanceRouter(reg)
        resp = router._send_request(
            {"host": "evil.com", "port": 8080}, "method", {},
        )
        assert "error" in resp
        assert "refused" in resp["error"]

    def test_registry_filters_loaded_non_localhost(self, tmp_path):
        """Registry filters non-localhost entries when loading from disk."""
        registry_path = str(tmp_path / "ssrf_load.json")
        # Write malicious data directly to file
        data = {
            "instances": {
                "legit": {
                    "host": "127.0.0.1", "port": 5000, "pid": 100,
                    "binary_name": "legit.exe",
                },
                "evil": {
                    "host": "attacker.com", "port": 9999, "pid": 666,
                    "binary_name": "evil.exe",
                },
            },
            "active_instance": None,
            "expired": {},
        }
        with open(registry_path, "w") as f:
            json.dump(data, f)

        reg = InstanceRegistry(registry_path)
        instances = reg.list_instances()
        assert "legit" in instances
        assert "evil" not in instances
