"""Tests for router.py — Request routing with mock HTTP."""

import json
import time
from unittest.mock import patch, MagicMock

import pytest

from ida_pro_mcp.registry import InstanceRegistry
from ida_pro_mcp.router import InstanceRouter


@pytest.fixture
def router_env(tmp_path):
    """Return (registry, router, instance_id) with one registered instance."""
    reg = InstanceRegistry(str(tmp_path / "inst.json"))
    iid = reg.register(
        pid=42, port=7000, idb_path="/test.i64",
        binary_name="test.exe", host="127.0.0.1",
    )
    router = InstanceRouter(reg)
    return reg, router, iid


@pytest.fixture
def multi_router_env(tmp_path):
    """Return (registry, router, iid1, iid2) with two registered instances."""
    reg = InstanceRegistry(str(tmp_path / "multi.json"))
    iid1 = reg.register(
        pid=42, port=7000, idb_path="/a.i64",
        binary_name="a.exe", host="127.0.0.1",
    )
    iid2 = reg.register(
        pid=43, port=7001, idb_path="/b.i64",
        binary_name="b.exe", host="127.0.0.1",
    )
    router = InstanceRouter(reg)
    return reg, router, iid1, iid2


class TestAutoRouting:
    def test_single_instance_auto_routes(self, router_env):
        """Single instance: request without instance_id auto-routes."""
        reg, router, iid = router_env
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "result": {"data": "ok"},
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "test.exe"}):
            with patch("http.client.HTTPConnection", return_value=mock_conn):
                resp = router.route_request("tools/call", {"arguments": {}})
        assert resp == {"data": "ok"}

    def test_no_instances_returns_error(self, tmp_path):
        """No instances registered: returns helpful error."""
        reg = InstanceRegistry(str(tmp_path / "empty.json"))
        router = InstanceRouter(reg)
        resp = router.route_request("tools/call", {"arguments": {}})
        assert "error" in resp
        assert "No IDA instances" in resp["error"]


class TestMissingInstanceId:
    def test_error_with_available_instances(self, multi_router_env):
        """Multiple instances + no instance_id: returns error with list."""
        reg, router, iid1, iid2 = multi_router_env
        resp = router.route_request("tools/call", {"arguments": {}})
        assert "error" in resp
        assert "instance_id" in resp["error"]
        assert "available_instances" in resp


class TestNonexistentInstance:
    def test_nonexistent_instance_error(self, router_env):
        """Requesting a non-existent instance returns error."""
        _, router, _ = router_env
        resp = router.route_request("tools/call",
                                    {"arguments": {"instance_id": "nope"}})
        assert "error" in resp
        assert "not found" in resp["error"]


class TestExpiredInstance:
    def test_expired_with_reason_and_replacements(self, multi_router_env):
        """Expired instance returns reason and replacement suggestions."""
        reg, router, iid1, iid2 = multi_router_env
        reg.expire_instance(iid1, reason="binary_changed", replaced_by=iid2)
        resp = router.route_request("tools/call",
                                    {"arguments": {"instance_id": iid1}})
        assert "error" in resp
        assert resp["reason"] == "binary_changed"

    def test_expired_no_replacement(self, router_env):
        """Expired instance with no replacement returns available list."""
        reg, router, iid = router_env
        # Register another, expire both => no replacement for binary
        iid2 = reg.register(
            pid=99, port=7099, idb_path="/other.i64",
            binary_name="other.exe", host="127.0.0.1",
        )
        reg.expire_instance(iid, reason="test_expire")
        resp = router.route_request("tools/call",
                                    {"arguments": {"instance_id": iid}})
        assert "error" in resp


class TestBinaryPathVerification:
    def _mock_metadata(self, module_name):
        return {"path": "/x.i64", "module": module_name}

    def test_match(self, router_env):
        """Binary path matches: verification succeeds."""
        _, router, iid = router_env
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value=self._mock_metadata("test.exe")):
            result = router._verify_binary_path(
                iid, {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000})
        assert result is True

    def test_mismatch(self, router_env):
        """Binary path mismatch: verification fails."""
        _, router, iid = router_env
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value=self._mock_metadata("other.exe")):
            result = router._verify_binary_path(
                iid, {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000})
        assert result is False

    def test_query_fails_returns_true(self, router_env):
        """When metadata query fails, assume valid (benefit of doubt)."""
        _, router, iid = router_env
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value=None):
            result = router._verify_binary_path(
                iid, {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000})
        assert result is True

    def test_case_insensitive_match(self, router_env):
        """Binary name comparison is case-insensitive."""
        _, router, iid = router_env
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value=self._mock_metadata("Test.EXE")):
            result = router._verify_binary_path(
                iid, {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000})
        assert result is True

    def test_backslash_normalization(self, router_env):
        """Windows backslash paths are normalized correctly."""
        _, router, iid = router_env
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "C:\\Users\\test\\test.exe"}):
            result = router._verify_binary_path(
                iid, {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000})
        assert result is True


class TestVerificationCache:
    def test_cache_hit(self, router_env):
        """Second call uses cached result (no HTTP query)."""
        _, router, iid = router_env
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "test.exe"}) as mock_query:
            info = {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000}
            router._verify_binary_path(iid, info)
            router._verify_binary_path(iid, info)
            assert mock_query.call_count == 1

    def test_cache_expiry(self, router_env):
        """Cache expires after timeout, triggering new query."""
        _, router, iid = router_env
        router._cache_timeout = 0  # expire immediately
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "test.exe"}) as mock_query:
            info = {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000}
            router._verify_binary_path(iid, info)
            time.sleep(0.01)
            router._verify_binary_path(iid, info)
            assert mock_query.call_count == 2


class TestSendRequest:
    def test_strips_instance_id(self, router_env):
        """instance_id is stripped from forwarded arguments."""
        _, router, iid = router_env
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "result": {"data": "ok"},
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "test.exe"}):
            with patch("http.client.HTTPConnection", return_value=mock_conn):
                router.route_request("tools/call", {
                    "arguments": {"instance_id": iid, "addr": "0x1000"},
                })

        # Verify instance_id was stripped
        call_args = mock_conn.request.call_args
        body = json.loads(call_args[0][2])
        assert "instance_id" not in body.get("params", {}).get("arguments", {})

    def test_ssrf_blocked(self, router_env):
        """Non-localhost host is rejected."""
        _, router, _ = router_env
        resp = router._send_request(
            {"host": "10.0.0.1", "port": 80}, "tools/call", {})
        assert "error" in resp
        assert "refused" in resp["error"]

    def test_connection_refused_error(self, router_env):
        """ConnectionRefusedError returns friendly error."""
        _, router, iid = router_env
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "test.exe"}):
            with patch("http.client.HTTPConnection") as mock_cls:
                mock_cls.return_value.request.side_effect = ConnectionRefusedError
                resp = router.route_request("tools/call", {
                    "arguments": {"instance_id": iid},
                })
        assert "error" in resp

    def test_timeout_error(self, router_env):
        """TimeoutError returns friendly error."""
        _, router, iid = router_env
        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "test.exe"}):
            with patch("http.client.HTTPConnection") as mock_cls:
                mock_cls.return_value.request.side_effect = TimeoutError
                resp = router.route_request("tools/call", {
                    "arguments": {"instance_id": iid},
                })
        assert "error" in resp
        assert "timed out" in resp["error"].lower() or "error" in resp

    def test_json_rpc_error_forwarded(self, router_env):
        """JSON-RPC error response is forwarded."""
        _, router, iid = router_env
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method not found"},
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("ida_pro_mcp.router.query_binary_metadata",
                   return_value={"module": "test.exe"}):
            with patch("http.client.HTTPConnection", return_value=mock_conn):
                resp = router.route_request("tools/call", {
                    "arguments": {"instance_id": iid},
                })
        assert "error" in resp
