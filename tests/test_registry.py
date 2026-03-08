"""Tests for registry.py — File-backed instance registry."""

import json
import os
import time

import pytest

from ida_pro_mcp.registry import (
    InstanceRegistry,
    MAX_INSTANCES,
    ALLOWED_HOSTS,
)


class TestRegister:
    def test_register_returns_instance_id(self, tmp_registry):
        """Register returns a non-empty string ID."""
        iid = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        assert isinstance(iid, str)
        assert len(iid) >= 4

    def test_register_stores_metadata(self, tmp_registry):
        """Registered instance metadata is retrievable."""
        iid = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="test.exe", host="127.0.0.1", arch="x64",
        )
        info = tmp_registry.get_instance(iid)
        assert info is not None
        assert info["pid"] == 100
        assert info["port"] == 5000
        assert info["binary_name"] == "test.exe"
        assert info["arch"] == "x64"

    def test_register_creates_json_file(self, tmp_registry):
        """Registry file is created on first registration."""
        tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        assert os.path.exists(tmp_registry.registry_path)
        with open(tmp_registry.registry_path, "r") as f:
            data = json.load(f)
        assert "instances" in data
        assert len(data["instances"]) == 1

    def test_register_auto_selects_first_active(self, tmp_registry):
        """First registered instance becomes the active instance."""
        iid = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        assert tmp_registry.get_active() == iid

    def test_register_rejects_non_localhost(self, tmp_registry):
        """Non-localhost hosts are rejected (SSRF protection)."""
        with pytest.raises(ValueError, match="Invalid host"):
            tmp_registry.register(
                pid=100, port=5000, idb_path="/tmp/a.i64",
                binary_name="a.exe", host="10.0.0.1",
            )

    def test_register_accepts_ipv6_localhost(self, tmp_registry):
        """IPv6 localhost (::1) is allowed."""
        iid = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="::1",
        )
        assert iid is not None

    def test_register_multiple_instances(self, tmp_registry):
        """Multiple different instances can be registered."""
        iid1 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        iid2 = tmp_registry.register(
            pid=200, port=5001, idb_path="/tmp/b.i64",
            binary_name="b.exe", host="127.0.0.1",
        )
        assert iid1 != iid2
        instances = tmp_registry.list_instances()
        assert len(instances) == 2

    def test_register_max_instances_limit(self, tmp_path):
        """Registry enforces MAX_INSTANCES limit."""
        reg = InstanceRegistry(str(tmp_path / "full.json"))
        for i in range(MAX_INSTANCES):
            reg.register(
                pid=i, port=5000 + i, idb_path=f"/tmp/{i}.i64",
                binary_name=f"bin{i}.exe", host="127.0.0.1",
            )
        with pytest.raises(ValueError, match="Registry full"):
            reg.register(
                pid=9999, port=9999, idb_path="/tmp/overflow.i64",
                binary_name="overflow.exe", host="127.0.0.1",
            )

    def test_register_extra_metadata(self, tmp_registry):
        """Extra keyword metadata is stored."""
        iid = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
            custom_field="custom_value",
        )
        info = tmp_registry.get_instance(iid)
        assert info["custom_field"] == "custom_value"


class TestUnregister:
    def test_unregister_removes_instance(self, populated_registry):
        """Unregistered instance is no longer listed."""
        instances = populated_registry.list_instances()
        iid = next(iter(instances))
        assert populated_registry.unregister(iid) is True
        assert populated_registry.get_instance(iid) is None

    def test_unregister_nonexistent_returns_false(self, tmp_registry):
        """Unregistering a non-existent ID returns False."""
        assert tmp_registry.unregister("nonexistent") is False

    def test_unregister_reassigns_active(self, tmp_registry):
        """Unregistering the active instance reassigns to next available."""
        iid1 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        iid2 = tmp_registry.register(
            pid=200, port=5001, idb_path="/tmp/b.i64",
            binary_name="b.exe", host="127.0.0.1",
        )
        assert tmp_registry.get_active() == iid1
        tmp_registry.unregister(iid1)
        assert tmp_registry.get_active() == iid2

    def test_unregister_last_clears_active(self, tmp_registry):
        """Unregistering the last instance sets active to None."""
        iid = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        tmp_registry.unregister(iid)
        assert tmp_registry.get_active() is None


class TestGetInstance:
    def test_get_existing(self, populated_registry):
        """Get returns correct metadata for existing instance."""
        instances = populated_registry.list_instances()
        iid = next(iter(instances))
        info = populated_registry.get_instance(iid)
        assert info is not None
        assert "pid" in info
        assert "port" in info

    def test_get_nonexistent(self, tmp_registry):
        """Get returns None for non-existent instance."""
        assert tmp_registry.get_instance("nonexistent") is None

    def test_get_returns_copy(self, populated_registry):
        """Returned dict is a copy, not a reference to internal data."""
        instances = populated_registry.list_instances()
        iid = next(iter(instances))
        info1 = populated_registry.get_instance(iid)
        info1["pid"] = 99999
        info2 = populated_registry.get_instance(iid)
        assert info2["pid"] != 99999


class TestListInstances:
    def test_empty_registry(self, tmp_registry):
        """Empty registry returns empty dict."""
        assert tmp_registry.list_instances() == {}

    def test_populated_registry(self, populated_registry):
        """Populated registry returns all instances."""
        instances = populated_registry.list_instances()
        assert len(instances) == 3


class TestHeartbeat:
    def test_update_heartbeat_success(self, populated_registry):
        """Update heartbeat returns True for existing instance."""
        iid = next(iter(populated_registry.list_instances()))
        assert populated_registry.update_heartbeat(iid) is True

    def test_update_heartbeat_nonexistent(self, tmp_registry):
        """Update heartbeat returns False for non-existent instance."""
        assert tmp_registry.update_heartbeat("nonexistent") is False

    def test_heartbeat_updates_timestamp(self, populated_registry):
        """Heartbeat actually updates the last_heartbeat field."""
        iid = next(iter(populated_registry.list_instances()))
        info_before = populated_registry.get_instance(iid)
        time.sleep(0.01)
        populated_registry.update_heartbeat(iid)
        info_after = populated_registry.get_instance(iid)
        assert info_after["last_heartbeat"] != info_before["last_heartbeat"]


class TestActiveInstance:
    def test_set_active_success(self, populated_registry):
        """Set active succeeds for existing instance."""
        instances = populated_registry.list_instances()
        iids = list(instances.keys())
        assert populated_registry.set_active(iids[1]) is True
        assert populated_registry.get_active() == iids[1]

    def test_set_active_nonexistent(self, tmp_registry):
        """Set active returns False for non-existent instance."""
        assert tmp_registry.set_active("nonexistent") is False


class TestExpireInstance:
    def test_expire_moves_to_expired(self, populated_registry):
        """Expired instance is moved from instances to expired."""
        instances = populated_registry.list_instances()
        iid = next(iter(instances))
        assert populated_registry.expire_instance(iid, reason="test_reason") is True
        assert populated_registry.get_instance(iid) is None
        expired = populated_registry.get_expired(iid)
        assert expired is not None
        assert expired["reason"] == "test_reason"

    def test_expire_nonexistent(self, tmp_registry):
        """Expiring non-existent instance returns False."""
        assert tmp_registry.expire_instance("nonexistent", reason="test") is False

    def test_expire_with_replacement(self, populated_registry):
        """Expire stores replaced_by field."""
        instances = populated_registry.list_instances()
        iids = list(instances.keys())
        populated_registry.expire_instance(
            iids[0], reason="binary_changed", replaced_by=iids[1],
        )
        expired = populated_registry.get_expired(iids[0])
        assert expired["replaced_by"] == iids[1]

    def test_expire_reassigns_active(self, tmp_registry):
        """Expiring active instance reassigns to remaining."""
        iid1 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        iid2 = tmp_registry.register(
            pid=200, port=5001, idb_path="/tmp/b.i64",
            binary_name="b.exe", host="127.0.0.1",
        )
        assert tmp_registry.get_active() == iid1
        tmp_registry.expire_instance(iid1, reason="test")
        assert tmp_registry.get_active() == iid2


class TestCleanup:
    def test_cleanup_expired_removes_old(self, tmp_registry):
        """cleanup_expired removes entries older than max_age."""
        iid = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        tmp_registry.expire_instance(iid, reason="test")
        # With max_age_seconds=0, everything is "old"
        removed = tmp_registry.cleanup_expired(max_age_seconds=0)
        assert removed >= 1
        assert tmp_registry.get_expired(iid) is None

    def test_cleanup_stale_by_heartbeat(self, tmp_registry):
        """cleanup_stale expires instances with timed-out heartbeat."""
        iid = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        # With timeout=0, everything is stale
        stale = tmp_registry.cleanup_stale(timeout_seconds=0)
        assert iid in stale
        assert tmp_registry.get_instance(iid) is None
        assert tmp_registry.get_expired(iid) is not None


class TestSSRFProtection:
    def test_load_filters_non_localhost(self, tmp_path):
        """Loading a registry with non-localhost hosts filters them out."""
        registry_path = str(tmp_path / "ssrf.json")
        data = {
            "instances": {
                "good": {"host": "127.0.0.1", "port": 5000, "pid": 100},
                "evil": {"host": "10.0.0.1", "port": 6000, "pid": 200},
            },
            "active_instance": None,
            "expired": {},
        }
        with open(registry_path, "w") as f:
            json.dump(data, f)

        reg = InstanceRegistry(registry_path)
        instances = reg.list_instances()
        assert "good" in instances
        assert "evil" not in instances


class TestCorruptedFile:
    def test_corrupted_file_recovered(self, tmp_path):
        """Corrupted registry file is quarantined and recovered."""
        registry_path = str(tmp_path / "corrupt.json")
        with open(registry_path, "w") as f:
            f.write("NOT VALID JSON{{{")

        reg = InstanceRegistry(registry_path)
        # Should recover gracefully
        instances = reg.list_instances()
        assert instances == {}

        # Should be able to register after recovery
        iid = reg.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        assert iid is not None


class TestReRegistration:
    """Tests for H5: re-registration cleanup of same pid+port instances."""

    def test_reregister_same_pid_port_expires_old(self, tmp_registry):
        """Re-registering with same pid+port expires the old instance."""
        iid1 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        # Re-register with same pid+port but different idb_path
        iid2 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/b.i64",
            binary_name="b.exe", host="127.0.0.1",
        )
        # Old instance should be expired
        assert tmp_registry.get_instance(iid1) is None
        expired = tmp_registry.get_expired(iid1)
        assert expired is not None
        assert expired["reason"] == "re_registered"
        # New instance should be active
        assert tmp_registry.get_instance(iid2) is not None
        assert len(tmp_registry.list_instances()) == 1

    def test_reregister_preserves_other_instances(self, tmp_registry):
        """Re-registration only affects instances with matching pid+port."""
        iid1 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        iid2 = tmp_registry.register(
            pid=200, port=5001, idb_path="/tmp/b.i64",
            binary_name="b.exe", host="127.0.0.1",
        )
        # Re-register pid=100, port=5000
        iid3 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/c.i64",
            binary_name="c.exe", host="127.0.0.1",
        )
        # iid2 should still be active
        assert tmp_registry.get_instance(iid2) is not None
        assert tmp_registry.get_instance(iid3) is not None
        assert tmp_registry.get_instance(iid1) is None
        assert len(tmp_registry.list_instances()) == 2

    def test_reregister_reassigns_active(self, tmp_registry):
        """If the active instance was re-registered, the new one becomes active."""
        iid1 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/a.i64",
            binary_name="a.exe", host="127.0.0.1",
        )
        assert tmp_registry.get_active() == iid1
        iid2 = tmp_registry.register(
            pid=100, port=5000, idb_path="/tmp/b.i64",
            binary_name="b.exe", host="127.0.0.1",
        )
        # New instance should become active (it's the only one or auto-selected)
        assert tmp_registry.get_active() == iid2


class TestQuarantineLogging:
    """Tests for H6: quarantine corrupted file logging."""

    def test_quarantine_logs_to_stderr(self, tmp_path, capsys):
        """Quarantine writes diagnostic info to stderr."""
        registry_path = str(tmp_path / "corrupt.json")
        with open(registry_path, "w") as f:
            f.write("NOT VALID JSON{{{")

        reg = InstanceRegistry(registry_path)
        # Trigger load, which detects corruption and quarantines
        reg.list_instances()

        captured = capsys.readouterr()
        assert "Quarantined corrupted registry" in captured.err
