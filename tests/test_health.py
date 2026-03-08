"""Tests for health.py — Process checks and auto-discovery."""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

from ida_pro_mcp.health import (
    is_process_alive,
    ping_instance,
    check_instance_health,
    query_binary_metadata,
    cleanup_stale_instances,
    rediscover_instances,
)
from ida_pro_mcp.registry import InstanceRegistry


class TestIsProcessAlive:
    def test_current_process_is_alive(self):
        """Current process should be detected as alive."""
        assert is_process_alive(os.getpid()) is True

    def test_nonexistent_pid(self):
        """Non-existent PID should be detected as dead."""
        # PID 2^30 is extremely unlikely to exist
        assert is_process_alive(2**30) is False


class TestPingInstance:
    def test_rejects_non_localhost(self):
        """Non-localhost hosts are rejected (SSRF protection)."""
        assert ping_instance("10.0.0.1", 5000) is False

    def test_unreachable_port(self):
        """Unreachable port returns False."""
        # Port 1 is almost certainly not listening
        assert ping_instance("127.0.0.1", 1, timeout=0.5) is False

    def test_successful_ping(self):
        """Successful ping returns True."""
        import json
        import http.client

        response_data = json.dumps({
            "jsonrpc": "2.0",
            "result": "pong",
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            assert ping_instance("127.0.0.1", 5000) is True


class TestCheckInstanceHealth:
    def test_dead_process_fails(self):
        """Instance with dead process fails health check."""
        instance = {"pid": 2**30, "host": "127.0.0.1", "port": 5000}
        assert check_instance_health(instance) is False

    def test_alive_process_but_no_http(self):
        """Alive process but no HTTP response fails health check."""
        instance = {"pid": os.getpid(), "host": "127.0.0.1", "port": 1}
        with patch("ida_pro_mcp.health.ping_instance", return_value=False):
            assert check_instance_health(instance) is False

    def test_fully_healthy(self):
        """Alive process + HTTP response passes health check."""
        instance = {"pid": os.getpid(), "host": "127.0.0.1", "port": 5000}
        with patch("ida_pro_mcp.health.ping_instance", return_value=True):
            assert check_instance_health(instance) is True


class TestQueryBinaryMetadata:
    def test_rejects_non_localhost(self):
        """Non-localhost hosts return None."""
        result = query_binary_metadata("10.0.0.1", 5000)
        assert result is None

    def test_successful_query(self):
        """Successful metadata query returns dict."""
        import json

        metadata = {"path": "/test.i64", "module": "test.exe", "arch": "x64"}
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "result": metadata,
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            result = query_binary_metadata("127.0.0.1", 5000)
        assert result == metadata

    def test_connection_failure_returns_none(self):
        """Connection failure returns None."""
        mock_conn = MagicMock()
        mock_conn.request.side_effect = ConnectionRefusedError
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            result = query_binary_metadata("127.0.0.1", 5000)
        assert result is None


class TestCleanupStaleInstances:
    def test_removes_dead_instances(self, tmp_path):
        """Dead process instances are expired."""
        reg = InstanceRegistry(str(tmp_path / "cleanup.json"))
        iid = reg.register(
            pid=2**30,  # non-existent PID
            port=5000, idb_path="/test.i64",
            binary_name="test.exe", host="127.0.0.1",
        )
        removed = cleanup_stale_instances(reg)
        assert iid in removed
        assert reg.get_instance(iid) is None

    def test_keeps_alive_instances(self, tmp_path):
        """Alive process instances are not removed."""
        reg = InstanceRegistry(str(tmp_path / "alive.json"))
        iid = reg.register(
            pid=os.getpid(),  # our own PID is alive
            port=5000, idb_path="/test.i64",
            binary_name="test.exe", host="127.0.0.1",
        )
        removed = cleanup_stale_instances(reg)
        assert iid not in removed
        assert reg.get_instance(iid) is not None


class TestRediscoverInstances:
    def test_no_ida_processes_found(self, tmp_path):
        """No IDA processes: returns empty list."""
        reg = InstanceRegistry(str(tmp_path / "empty.json"))
        with patch("ida_pro_mcp.health._find_ida_listening_ports", return_value=[]):
            result = rediscover_instances(reg)
        assert result == []

    def test_discovers_new_instance(self, tmp_path):
        """New IDA instance is discovered and registered."""
        import json

        reg = InstanceRegistry(str(tmp_path / "discover.json"))
        metadata = {"path": "/bin.i64", "module": "bin.exe", "arch": "x64"}

        with patch("ida_pro_mcp.health._find_ida_listening_ports",
                   return_value=[(1234, 7000)]):
            with patch("ida_pro_mcp.health.ping_instance", return_value=True):
                with patch("ida_pro_mcp.health.query_binary_metadata",
                           return_value=metadata):
                    result = rediscover_instances(reg)

        assert len(result) == 1
        instances = reg.list_instances()
        assert len(instances) == 1

    def test_skips_already_registered(self, tmp_path):
        """Already-known instances are not re-registered."""
        reg = InstanceRegistry(str(tmp_path / "skip.json"))
        iid = reg.register(
            pid=1234, port=7000, idb_path="/bin.i64",
            binary_name="bin.exe", host="127.0.0.1",
        )

        with patch("ida_pro_mcp.health._find_ida_listening_ports",
                   return_value=[(1234, 7000)]):
            result = rediscover_instances(reg)

        assert result == []
        instances = reg.list_instances()
        assert len(instances) == 1  # no duplicate

    def test_skips_non_mcp_servers(self, tmp_path):
        """Non-MCP HTTP servers are not registered."""
        reg = InstanceRegistry(str(tmp_path / "nonmcp.json"))

        with patch("ida_pro_mcp.health._find_ida_listening_ports",
                   return_value=[(1234, 8080)]):
            with patch("ida_pro_mcp.health.ping_instance", return_value=False):
                result = rediscover_instances(reg)

        assert result == []
