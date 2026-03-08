"""Request routing for IDA Pro MCP multi-instance support.

Routes MCP tool requests to the appropriate IDA instance based on the
``instance_id`` parameter, with fallback binary verification and
friendly error messages for expired/missing instances.

Adapted from ida-multi-mcp project.
"""

from __future__ import annotations

import http.client
import json
import os
import time
from typing import Any

from .health import query_binary_metadata
from .registry import ALLOWED_HOSTS, InstanceRegistry


class InstanceRouter:
    """Routes MCP tool requests to IDA instances.

    Handles ``instance_id`` extraction, binary verification, error
    handling, and transparent single-instance auto-routing.
    """

    def __init__(self, registry: InstanceRegistry) -> None:
        self.registry = registry
        # Cache: instance_id -> (normalized_binary_name, timestamp)
        self._binary_path_cache: dict[str, tuple[str | None, float]] = {}
        self._cache_timeout = 60.0  # seconds (aligned with heartbeat interval)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Route a tool request to the appropriate IDA instance.

        **Auto-routing**: When only one instance is registered and
        ``instance_id`` is omitted, the request is routed automatically.

        Args:
            method: JSON-RPC method name (e.g., ``"get_metadata"``).
            params: Method parameters dict.  May contain
                ``arguments.instance_id``.

        Returns:
            Result dict from the IDA instance, or an error dict.
        """
        # Extract instance_id from params
        arguments = params.get("arguments", {})
        instance_id: str | None = arguments.get("instance_id")

        # Auto-route: single instance -> use it automatically
        if not instance_id:
            instances = self.registry.list_instances()
            if len(instances) == 1:
                instance_id = next(iter(instances))
            elif len(instances) == 0:
                return {
                    "error": "No IDA instances registered.",
                    "hint": (
                        "Open a binary in IDA Pro with the MCP plugin loaded, "
                        "or run refresh_instances() to auto-discover."
                    ),
                }
            else:
                # Multiple instances: require explicit instance_id
                return {
                    "error": "Missing required parameter 'instance_id'.",
                    "hint": (
                        "Multiple IDA instances are registered. "
                        "Call list_instances() and pass instance_id "
                        "explicitly for every IDA tool call."
                    ),
                    "available_instances": [
                        {"id": iid, "binary_name": info.get("binary_name", "unknown")}
                        for iid, info in instances.items()
                    ],
                }

        # Get instance info
        instance_info = self.registry.get_instance(instance_id)

        if instance_info is None:
            expired_info = self.registry.get_expired(instance_id)
            if expired_info is not None:
                return self._handle_expired_instance(instance_id, expired_info)
            return self._handle_missing_instance(instance_id)

        # Verify binary path (5s cached fallback check)
        if not self._verify_binary_path(instance_id, instance_info):
            return {
                "error": f"Instance '{instance_id}' binary path changed. Instance may be stale.",
                "hint": "Use list_instances() to see current instances.",
            }

        # Remove instance_id from arguments before forwarding
        forward_params = params.copy()
        if "arguments" in forward_params:
            forward_args = dict(forward_params["arguments"])
            forward_args.pop("instance_id", None)
            forward_params["arguments"] = forward_args

        return self._send_request(instance_info, method, forward_params)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_binary_path(self, instance_id: str, instance_info: dict[str, Any]) -> bool:
        """Verify instance is still analysing the same binary.

        Uses a 5-second cache to avoid excessive HTTP queries.
        Returns ``True`` when verification is inconclusive (benefit of doubt).
        """
        now = time.time()

        def _normalize(name: str | None) -> str | None:
            if not name:
                return None
            n = os.path.basename(name.replace("\\", "/")).strip()
            return n.casefold() if n else None

        # Check cache
        if instance_id in self._binary_path_cache:
            cached_name, cached_time = self._binary_path_cache[instance_id]
            if now - cached_time < self._cache_timeout:
                return cached_name == _normalize(instance_info.get("binary_name"))

        # Fresh query
        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")
        metadata = query_binary_metadata(host, port)

        current_name = _normalize(metadata.get("module") if metadata else None)
        self._binary_path_cache[instance_id] = (current_name, now)

        # Can't query -> assume valid
        if current_name is None:
            return True

        return current_name == _normalize(instance_info.get("binary_name"))

    def _send_request(
        self,
        instance_info: dict[str, Any],
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Send JSON-RPC request to an IDA instance over HTTP.

        Args:
            instance_info: Instance metadata (must have ``host`` and ``port``).
            method: JSON-RPC method name.
            params: Routing params dict. If it contains ``method_params``,
                those are used as the JSON-RPC positional params list.
                Otherwise the entire dict is forwarded.

        Returns:
            ``result`` field from the JSON-RPC response, or an error dict.
        """
        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")

        # SSRF protection
        if host not in ALLOWED_HOSTS:
            return {"error": "Connection refused: only localhost instances allowed"}

        # Extract positional params for the IDA JSON-RPC endpoint
        rpc_params = params.get("method_params", params)

        conn = http.client.HTTPConnection(host, port, timeout=300.0)
        try:
            body = json.dumps({
                "jsonrpc": "2.0",
                "method": method,
                "params": rpc_params,
                "id": 1,
            })
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = json.loads(response.read().decode())

            if "result" in data:
                return data["result"]
            if "error" in data:
                return {"error": data["error"]}
            return data
        except ConnectionRefusedError:
            return {
                "error": f"Instance '{instance_info.get('binary_name', 'unknown')}' "
                         f"is not responding (connection refused).",
                "hint": "The IDA instance may have been closed. Run refresh_instances().",
            }
        except TimeoutError:
            return {
                "error": "Request timed out. IDA may be busy with a long operation.",
                "hint": "IDA runs on a single thread. Wait and retry.",
            }
        except (OSError, http.client.HTTPException) as e:
            return {"error": f"Failed to connect to instance: {type(e).__name__}: {e}"}
        except Exception as e:
            return {"error": f"Unexpected error communicating with instance: {type(e).__name__}: {e}"}
        finally:
            conn.close()

    def _handle_expired_instance(
        self,
        instance_id: str,
        expired_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Return helpful error for an expired instance with replacement suggestions."""
        binary_name = expired_info.get("binary_name", "")
        instances = self.registry.list_instances()

        # Find replacements analysing the same binary
        replacements = [
            (iid, info)
            for iid, info in instances.items()
            if info.get("binary_name") == binary_name
        ]

        reason = expired_info.get("reason", "unknown")
        if replacements:
            return {
                "error": f"Instance '{instance_id}' expired at "
                         f"{expired_info.get('expired_at')}",
                "reason": reason,
                "replacements": [
                    {"id": iid, "binary_name": info.get("binary_name")}
                    for iid, info in replacements
                ],
                "hint": f"Use instance_id='{replacements[0][0]}' for subsequent calls.",
            }
        return {
            "error": f"Instance '{instance_id}' expired and no replacement found.",
            "reason": reason,
            "available_instances": list(instances.keys()),
        }

    def _handle_missing_instance(self, instance_id: str) -> dict[str, Any]:
        """Return helpful error for a completely unknown instance ID."""
        instances = self.registry.list_instances()
        return {
            "error": f"Instance '{instance_id}' not found.",
            "available_instances": [
                {"id": iid, "binary_name": info.get("binary_name", "unknown")}
                for iid, info in instances.items()
            ],
            "hint": "Use list_instances() to see all available instances.",
        }
