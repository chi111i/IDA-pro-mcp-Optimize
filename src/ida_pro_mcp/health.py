"""Health check module for IDA Pro MCP multi-instance support.

Detects dead/stale IDA instances via process-alive check and HTTP ping.
Supports auto-rediscovery of live IDA MCP servers on proxy restart.

Adapted from ida-multi-mcp project.
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .registry import InstanceRegistry

# Only allow localhost connections (SSRF protection)
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# Known IDA Pro executable names
_IDA_PROCESS_NAMES = frozenset({
    "ida.exe", "ida64.exe", "idat.exe", "idat64.exe",
    "ida", "ida64", "idat", "idat64",
})


# ------------------------------------------------------------------
# Process-level checks
# ------------------------------------------------------------------

def is_process_alive(pid: int) -> bool:
    """Check if a process is still running (cross-platform).

    Args:
        pid: Process ID to check.

    Returns:
        True if the process exists.
    """
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # Process exists but we can't signal it


# ------------------------------------------------------------------
# HTTP-level checks
# ------------------------------------------------------------------

def ping_instance(host: str, port: int, timeout: float = 5.0) -> bool:
    """Ping an IDA instance via HTTP JSON-RPC ping.

    Args:
        host: Instance hostname (must be localhost).
        port: Instance port.
        timeout: Connection timeout in seconds.

    Returns:
        True if instance responds to ping with HTTP 200.
    """
    if host not in _ALLOWED_HOSTS:
        return False
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1})
        conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status == 200
    except Exception:
        return False
    finally:
        conn.close()


def check_instance_health(instance: dict[str, Any]) -> bool:
    """Check if an IDA instance is alive and responsive.

    Performs two checks:
        1. Process alive (OS-level)
        2. HTTP ping (application-level)

    Args:
        instance: Instance info dict with ``pid``, ``host``, ``port``.

    Returns:
        True if instance is healthy.
    """
    if not is_process_alive(instance["pid"]):
        return False
    return ping_instance(instance["host"], instance["port"])


def query_binary_metadata(host: str, port: int, timeout: float = 5.0) -> dict[str, Any] | None:
    """Query an IDA instance for its current binary metadata.

    Uses the ``get_metadata`` JSON-RPC method to get current file info.
    This is the fallback mechanism for detecting binary changes when
    IDA hooks don't fire.

    Args:
        host: Instance hostname (must be localhost).
        port: Instance port.
        timeout: Connection timeout.

    Returns:
        Metadata dict with ``path`` (input file), ``module`` (root filename),
        ``base``, ``size``, etc. — or ``None`` on failure.
    """
    if host not in _ALLOWED_HOSTS:
        return None
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": "get_metadata",
            "params": {},
            "id": 1,
        })
        conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = json.loads(response.read().decode())

        result = data.get("result")
        if isinstance(result, dict):
            return result
    except Exception:
        pass
    finally:
        conn.close()
    return None


# ------------------------------------------------------------------
# Registry cleanup
# ------------------------------------------------------------------

def cleanup_stale_instances(
    registry: InstanceRegistry,
    timeout_seconds: int = 120,
) -> list[str]:
    """Remove dead instances from registry.

    Only removes instances whose IDA process is no longer running.
    Instances that are alive but not responding to ping (e.g., busy
    with a long decompilation) are kept — IDA runs on a single main
    thread and cannot answer pings while processing a request.

    Also cleans up old expired entries.

    Args:
        registry: The instance registry.
        timeout_seconds: Heartbeat timeout threshold.

    Returns:
        List of removed instance IDs.
    """
    removed: list[str] = []
    instances = registry.list_instances()

    for instance_id, info in instances.items():
        pid = info.get("pid")
        if pid is not None and not is_process_alive(pid):
            registry.expire_instance(instance_id, reason="process_dead")
            removed.append(instance_id)
            print(
                f"[ida-pro-mcp] Removed dead instance '{instance_id}' "
                f"(pid {pid}, {info.get('binary_name', 'unknown')})",
                file=sys.stderr,
            )

    # Also clean up old expired entries
    registry.cleanup_expired()

    return removed


# ------------------------------------------------------------------
# Auto-discovery
# ------------------------------------------------------------------

def _find_ida_listening_ports() -> list[tuple[int, int]]:
    """Find TCP ports owned by IDA processes.

    Returns:
        List of ``(pid, port)`` tuples for IDA processes with
        listening TCP ports.
    """
    results: list[tuple[int, int]] = []

    if sys.platform == "win32":
        results = _find_ida_ports_windows()
    else:
        results = _find_ida_ports_unix()

    return results


def _find_ida_ports_windows() -> list[tuple[int, int]]:
    """Windows implementation: tasklist + netstat."""
    results: list[tuple[int, int]] = []
    try:
        # Get IDA PIDs
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )
        ida_pids: set[int] = set()
        for line in out.strip().splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() in _IDA_PROCESS_NAMES:
                try:
                    ida_pids.add(int(parts[1]))
                except ValueError:
                    pass

        if not ida_pids:
            return []

        # Get listening ports for those PIDs
        out = subprocess.check_output(
            ["netstat", "-ano", "-p", "TCP"],
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "LISTENING":
                try:
                    pid = int(parts[4])
                except ValueError:
                    continue
                if pid in ida_pids:
                    port_str = parts[1].rsplit(":", 1)[-1]
                    try:
                        results.append((pid, int(port_str)))
                    except ValueError:
                        pass
    except (subprocess.SubprocessError, OSError):
        pass
    return results


def _find_ida_ports_unix() -> list[tuple[int, int]]:
    """Unix implementation: lsof or ss."""
    results: list[tuple[int, int]] = []

    # Try lsof first
    try:
        out = subprocess.check_output(
            ["lsof", "-iTCP", "-sTCP:LISTEN", "-nP", "-F", "pcn"],
            text=True,
            timeout=10,
        )
        current_pid: int | None = None
        current_name: str | None = None
        for line in out.splitlines():
            if line.startswith("p"):
                current_pid = int(line[1:])
                current_name = None  # Reset name for each new process
            elif line.startswith("c"):
                current_name = line[1:]
            elif line.startswith("n") and current_pid and current_name:
                if current_name.lower() in _IDA_PROCESS_NAMES:
                    port_str = line.rsplit(":", 1)[-1]
                    try:
                        results.append((current_pid, int(port_str)))
                    except ValueError:
                        pass
        return results
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass

    # Fallback: ss
    try:
        import re

        out = subprocess.check_output(["ss", "-tlnp"], text=True, timeout=10)
        for line in out.splitlines():
            for name in _IDA_PROCESS_NAMES:
                if name in line:
                    parts = line.split()
                    for part in parts:
                        if ":" in part:
                            port_str = part.rsplit(":", 1)[-1]
                            try:
                                port = int(port_str)
                                m = re.search(r"pid=(\d+)", line)
                                if m:
                                    results.append((int(m.group(1)), port))
                                break
                            except ValueError:
                                continue
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass

    return results


def rediscover_instances(registry: InstanceRegistry) -> list[str]:
    """Auto-discover live IDA MCP servers and register them.

    Scans for running IDA processes, finds their listening TCP ports,
    pings each to confirm it's an MCP server, queries metadata, and
    registers any that aren't already in the registry.

    Typically called on MCP server startup when the registry is empty.

    Args:
        registry: The instance registry.

    Returns:
        List of newly registered instance IDs.
    """
    registered: list[str] = []
    existing = registry.list_instances()

    # Skip already-known (pid, port) pairs
    known_ports = {
        (info["pid"], info["port"])
        for info in existing.values()
        if "pid" in info and "port" in info
    }

    candidates = _find_ida_listening_ports()
    if not candidates:
        return []

    for pid, port in candidates:
        if (pid, port) in known_ports:
            continue

        host = "127.0.0.1"

        # Confirm it's an MCP server
        if not ping_instance(host, port, timeout=5.0):
            continue

        # Query metadata for binary info
        metadata = query_binary_metadata(host, port, timeout=5.0)
        if not metadata:
            continue

        try:
            idb_path = metadata.get("path", "")
            binary_name = metadata.get("module", "unknown")

            instance_id = registry.register(
                pid=pid,
                port=port,
                idb_path=idb_path,
                binary_name=binary_name,
                binary_path=metadata.get("path", ""),
                arch=metadata.get("arch", "unknown"),
                host=host,
            )
            registered.append(instance_id)
            print(
                f"[ida-pro-mcp] Auto-discovered instance '{instance_id}' "
                f"(pid {pid}, port {port}, {binary_name})",
                file=sys.stderr,
            )
        except Exception as e:
            print(f"[ida-pro-mcp] Failed to register discovered instance: {e}", file=sys.stderr)

    return registered
