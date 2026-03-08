"""Instance registry for IDA Pro MCP multi-instance support.

Manages the global registry of IDA Pro instances with atomic file operations
and file-level locking. Registry data is stored in ~/.ida-mcp/instances.json.

Adapted from ida-multi-mcp project.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .filelock import FileLock
from .instance_id import generate_instance_id, resolve_collision

# Environment variable to override the default registry path
REGISTRY_PATH_ENV = "IDA_MCP_REGISTRY_PATH"

# Safety limits to prevent unbounded growth
MAX_INSTANCES = 100
MAX_EXPIRED = 200

# Only allow localhost connections (SSRF protection)
ALLOWED_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def get_default_registry_path() -> str:
    """Resolve default registry path.

    Resolution order:
        1. ``IDA_MCP_REGISTRY_PATH`` environment variable
        2. ``~/.ida-mcp/instances.json``
    """
    override = os.environ.get(REGISTRY_PATH_ENV, "").strip()
    if override:
        return override
    return str(Path.home() / ".ida-mcp" / "instances.json")


class InstanceRegistry:
    """File-backed registry of IDA Pro instances.

    Stores instance metadata in ``~/.ida-mcp/instances.json`` protected
    by a cross-platform file lock.  Tracks active instances, expired
    instances, and the currently selected active instance.

    All public methods are safe for multi-process access.
    """

    def __init__(self, registry_path: str | None = None) -> None:
        """
        Args:
            registry_path: Path to registry JSON file.
                Defaults to ``~/.ida-mcp/instances.json``.
        """
        if registry_path is None:
            registry_path = get_default_registry_path()

        self.registry_path = registry_path
        self.lock_path = registry_path + ".lock"

        # Ensure parent directory exists with restrictive permissions
        registry_dir = os.path.dirname(self.registry_path)
        if registry_dir and not os.path.exists(registry_dir):
            os.makedirs(registry_dir, exist_ok=True)
            if sys.platform != "win32":
                os.chmod(registry_dir, stat.S_IRWXU)  # 0o700

    # ------------------------------------------------------------------
    # Internal helpers (caller must hold the file lock)
    # ------------------------------------------------------------------

    @staticmethod
    def _iso_timestamp() -> str:
        """Generate ISO 8601 UTC timestamp string."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> float:
        """Parse ISO 8601 timestamp to Unix epoch seconds.

        Returns 0.0 on parse failure (treated as infinitely old).
        """
        try:
            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, AttributeError):
            return 0.0

    def _load(self) -> dict[str, Any]:
        """Load registry data from disk.  Must be called with lock held."""
        try:
            with open(self.registry_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Registry root must be a JSON object")
        except FileNotFoundError:
            return {"instances": {}, "active_instance": None, "expired": {}}
        except Exception:
            # Quarantine corrupted file and recover with empty registry
            self._quarantine_corrupted_file()
            return {"instances": {}, "active_instance": None, "expired": {}}

        # Normalize missing keys from older schema variants
        data.setdefault("instances", {})
        data.setdefault("active_instance", None)
        data.setdefault("expired", {})

        # Security: reject entries with non-localhost hosts (SSRF protection)
        for iid in list(data["instances"].keys()):
            host = data["instances"][iid].get("host", "127.0.0.1")
            if host not in ALLOWED_HOSTS:
                del data["instances"][iid]

        return data

    def _quarantine_corrupted_file(self) -> None:
        """Move corrupted registry file to a .corrupt-<uuid> backup."""
        try:
            import uuid

            suffix = uuid.uuid4().hex[:8]
            corrupt_path = f"{self.registry_path}.corrupt-{suffix}"
            os.replace(self.registry_path, corrupt_path)
            print(
                f"[ida-pro-mcp] Quarantined corrupted registry: {corrupt_path}",
                file=sys.stderr,
            )
        except Exception as exc:
            print(
                f"[ida-pro-mcp] Failed to quarantine corrupted registry: {exc}",
                file=sys.stderr,
            )

    def _save(self, data: dict[str, Any]) -> None:
        """Save registry data to disk atomically.  Must be called with lock held."""
        temp_fd: int | None = None
        temp_path: str | None = None
        try:
            # Create temp file in the same directory for atomic rename
            temp_fd, temp_path = tempfile.mkstemp(
                prefix="instances.",
                suffix=".tmp",
                dir=os.path.dirname(self.registry_path) or ".",
            )
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                temp_fd = None  # fdopen takes ownership
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Atomic rename (POSIX guarantees; Windows best-effort)
            os.replace(temp_path, self.registry_path)
            temp_path = None

            # Restrictive permissions on Unix (owner read/write only)
            if sys.platform != "win32":
                os.chmod(self.registry_path, stat.S_IRUSR | stat.S_IWUSR)
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            if temp_path is not None:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self, pid: int, port: int, idb_path: str, **metadata: Any) -> str:
        """Register a new IDA instance.

        Args:
            pid: Process ID of the IDA process.
            port: TCP port the MCP HTTP server is bound to.
            idb_path: Absolute path to the IDB file being analyzed.
            **metadata: Extra metadata (``binary_name``, ``binary_path``,
                ``arch``, ``host``, etc.).

        Returns:
            Generated instance ID (4-char base36 string).

        Raises:
            ValueError: If registry is full or host is not localhost.
        """
        with FileLock(self.lock_path):
            data = self._load()

            # Resource exhaustion protection
            if len(data["instances"]) >= MAX_INSTANCES:
                raise ValueError(
                    f"Registry full: maximum {MAX_INSTANCES} instances allowed. "
                    "Remove stale instances first."
                )

            # SSRF protection
            host = metadata.get("host", "127.0.0.1")
            if host not in ALLOWED_HOSTS:
                raise ValueError(
                    f"Invalid host '{host}': only localhost connections allowed"
                )

            # Clean up stale entries with the same pid+port (re-registration)
            for old_id in list(data["instances"].keys()):
                old = data["instances"][old_id]
                if old.get("pid") == pid and old.get("port") == port:
                    data["expired"][old_id] = {
                        "binary_name": old.get("binary_name", "unknown"),
                        "binary_path": old.get("binary_path", ""),
                        "expired_at": self._iso_timestamp(),
                        "reason": "re_registered",
                    }
                    del data["instances"][old_id]
                    if data["active_instance"] == old_id:
                        data["active_instance"] = None

            existing_ids = set(data["instances"].keys())

            # Generate and resolve instance ID
            candidate_id = generate_instance_id(pid, port, idb_path)
            instance_id = resolve_collision(candidate_id, existing_ids, pid, port, idb_path)

            # Build instance info
            now = self._iso_timestamp()
            instance_info: dict[str, Any] = {
                "pid": pid,
                "host": host,
                "port": port,
                "binary_name": metadata.get("binary_name", "unknown"),
                "binary_path": metadata.get("binary_path", ""),
                "idb_path": idb_path,
                "arch": metadata.get("arch", "unknown"),
                "registered_at": now,
                "last_heartbeat": now,
            }
            # Merge extra metadata (without overwriting required fields)
            for key, value in metadata.items():
                if key not in instance_info:
                    instance_info[key] = value

            data["instances"][instance_id] = instance_info

            # Auto-select first instance as active
            if data["active_instance"] is None:
                data["active_instance"] = instance_id

            self._save(data)
            return instance_id

    def unregister(self, instance_id: str) -> bool:
        """Remove an instance from the registry.

        Returns:
            True if instance was found and removed.
        """
        with FileLock(self.lock_path):
            data = self._load()

            if instance_id not in data["instances"]:
                return False

            del data["instances"][instance_id]

            # Reassign active instance if needed (prefer most recently seen)
            if data["active_instance"] == instance_id:
                remaining = list(data["instances"].keys())
                if remaining:
                    data["active_instance"] = max(
                        remaining,
                        key=lambda k: data["instances"][k].get("last_heartbeat", ""),
                    )
                else:
                    data["active_instance"] = None

            self._save(data)
            return True

    def get_instance(self, instance_id: str) -> dict[str, Any] | None:
        """Get metadata for a specific instance.

        Returns:
            Instance metadata dict, or ``None`` if not registered.
        """
        with FileLock(self.lock_path):
            data = self._load()
            info = data["instances"].get(instance_id)
            return dict(info) if info is not None else None

    def list_instances(self) -> dict[str, dict[str, Any]]:
        """List all registered (active) instances.

        Returns:
            Dict mapping ``instance_id`` -> metadata.
        """
        with FileLock(self.lock_path):
            data = self._load()
            return {k: dict(v) for k, v in data["instances"].items()}

    def update_heartbeat(self, instance_id: str) -> bool:
        """Update the last heartbeat timestamp for an instance.

        Returns:
            True if instance was found and updated.
        """
        with FileLock(self.lock_path):
            data = self._load()

            if instance_id not in data["instances"]:
                return False

            data["instances"][instance_id]["last_heartbeat"] = self._iso_timestamp()
            self._save(data)
            return True

    def get_active(self) -> str | None:
        """Get the currently active instance ID."""
        with FileLock(self.lock_path):
            data = self._load()
            return data["active_instance"]

    def set_active(self, instance_id: str) -> bool:
        """Set the active instance.

        Returns:
            True if instance exists and was set active.
        """
        with FileLock(self.lock_path):
            data = self._load()

            if instance_id not in data["instances"]:
                return False

            data["active_instance"] = instance_id
            self._save(data)
            return True

    def expire_instance(
        self,
        instance_id: str,
        reason: str,
        replaced_by: str | None = None,
    ) -> bool:
        """Move an instance to the expired list.

        Expired instances are kept for a limited time so that clients
        referencing old IDs receive helpful error messages suggesting
        the replacement instance.

        Args:
            instance_id: Instance to expire.
            reason: Expiration reason (e.g., ``"binary_changed"``,
                ``"ida_closed"``, ``"stale_heartbeat"``).
            replaced_by: ID of the instance that replaced this one.

        Returns:
            True if instance was found and expired.
        """
        with FileLock(self.lock_path):
            data = self._load()

            if instance_id not in data["instances"]:
                return False

            instance = data["instances"][instance_id]
            expired_info: dict[str, Any] = {
                "binary_name": instance.get("binary_name", "unknown"),
                "binary_path": instance.get("binary_path", ""),
                "expired_at": self._iso_timestamp(),
                "reason": reason,
            }
            if replaced_by is not None:
                expired_info["replaced_by"] = replaced_by

            data["expired"][instance_id] = expired_info
            del data["instances"][instance_id]

            # Reassign active instance if needed (prefer most recently seen)
            if data["active_instance"] == instance_id:
                remaining = list(data["instances"].keys())
                if remaining:
                    data["active_instance"] = max(
                        remaining,
                        key=lambda k: data["instances"][k].get("last_heartbeat", ""),
                    )
                else:
                    data["active_instance"] = None

            self._save(data)
            return True

    def get_expired(self, instance_id: str) -> dict[str, Any] | None:
        """Get metadata for a specific expired instance.

        Returns:
            Expired instance metadata dict, or ``None`` if not found.
        """
        with FileLock(self.lock_path):
            data = self._load()
            info = data.get("expired", {}).get(instance_id)
            return dict(info) if info is not None else None

    def cleanup_expired(self, max_age_seconds: int = 3600) -> int:
        """Remove expired instances older than *max_age_seconds*.

        Also enforces the ``MAX_EXPIRED`` cap.

        Returns:
            Number of removed expired entries.
        """
        with FileLock(self.lock_path):
            data = self._load()
            expired = data.get("expired", {})
            now = time.time()
            removed = 0

            for iid in list(expired.keys()):
                expired_at = self._parse_timestamp(expired[iid].get("expired_at", ""))
                if now - expired_at > max_age_seconds:
                    del expired[iid]
                    removed += 1

            # Cap expired list size
            while len(expired) > MAX_EXPIRED:
                oldest_key = next(iter(expired))
                del expired[oldest_key]
                removed += 1

            data["expired"] = expired
            self._save(data)
            return removed

    def cleanup_stale(self, timeout_seconds: int = 120) -> list[str]:
        """Expire instances whose heartbeat has timed out.

        Args:
            timeout_seconds: Heartbeat staleness threshold (default 120s).

        Returns:
            List of expired instance IDs.
        """
        with FileLock(self.lock_path):
            data = self._load()
            now = time.time()
            stale: list[str] = []

            for iid in list(data["instances"].keys()):
                info = data["instances"][iid]
                last_hb = self._parse_timestamp(info.get("last_heartbeat", ""))
                if now - last_hb > timeout_seconds:
                    expired_info: dict[str, Any] = {
                        "binary_name": info.get("binary_name", "unknown"),
                        "binary_path": info.get("binary_path", ""),
                        "expired_at": self._iso_timestamp(),
                        "reason": "stale_heartbeat",
                    }
                    data["expired"][iid] = expired_info
                    del data["instances"][iid]
                    stale.append(iid)

            # Reassign active instance if it became stale (prefer most recently seen)
            if data["active_instance"] in stale:
                remaining = list(data["instances"].keys())
                if remaining:
                    data["active_instance"] = max(
                        remaining,
                        key=lambda k: data["instances"][k].get("last_heartbeat", ""),
                    )
                else:
                    data["active_instance"] = None

            self._save(data)
            return stale
