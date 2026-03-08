"""Instance ID generation for IDA Pro MCP multi-instance support.

Generates deterministic, short, human-readable base36 IDs from (pid, port, idb_path).
IDs change when the binary changes, ensuring generation-based uniqueness.

Adapted from ida-multi-mcp project.
"""

import hashlib

BASE36_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"
DEFAULT_ID_LENGTH = 4


def generate_instance_id(pid: int, port: int, idb_path: str, length: int = DEFAULT_ID_LENGTH) -> str:
    """Generate a base36 instance ID from pid, port, and IDB path.

    The same (pid, port, idb_path) tuple always produces the same ID,
    providing deterministic identification. Different IDB paths produce
    different IDs, so reopening a new binary triggers a new ID.

    Args:
        pid: Process ID of the IDA instance.
        port: Port number the MCP HTTP server is bound to.
        idb_path: Absolute path to the IDB file being analyzed.
        length: ID length (default 4 chars = ~1.68M combinations).

    Returns:
        Base36 string of specified length (e.g., "k7m2").
    """
    raw = hashlib.sha256(f"{pid}:{port}:{idb_path}".encode()).digest()
    n = int.from_bytes(raw[:4], "big") % (36 ** length)
    result = ""
    for _ in range(length):
        result = BASE36_CHARS[n % 36] + result
        n //= 36
    return result


def resolve_collision(
    candidate: str,
    existing_ids: set[str],
    pid: int,
    port: int,
    idb_path: str,
) -> str:
    """Resolve an ID collision by expanding to longer IDs.

    Strategy:
    1. If no collision, return the candidate as-is.
    2. Expand to (length+1) characters using the same hash.
    3. Last resort: append incrementing base36 suffix.

    Args:
        candidate: The initial 4-char ID that may collide.
        existing_ids: Set of currently registered instance IDs.
        pid: Process ID.
        port: Port number.
        idb_path: IDB path.

    Returns:
        A unique ID guaranteed not to exist in existing_ids.

    Raises:
        RuntimeError: If all suffix combinations are exhausted (extremely unlikely).
    """
    if candidate not in existing_ids:
        return candidate

    # Expand to 5 characters using the same hash source
    expanded = generate_instance_id(pid, port, idb_path, length=DEFAULT_ID_LENGTH + 1)
    if expanded not in existing_ids:
        return expanded

    # Last resort: append incrementing suffix (up to 2 chars = 1296 combinations)
    for i in range(36):
        suffixed = candidate + BASE36_CHARS[i]
        if suffixed not in existing_ids:
            return suffixed

    for i in range(36):
        for j in range(36):
            suffixed = candidate + BASE36_CHARS[i] + BASE36_CHARS[j]
            if suffixed not in existing_ids:
                return suffixed

    raise RuntimeError(f"Cannot generate unique instance ID (tried {36 + 36*36} suffixes)")
