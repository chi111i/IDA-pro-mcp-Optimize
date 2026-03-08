"""Cross-platform file locking for IDA Pro MCP multi-instance support.

Provides mutual exclusion for the instance registry file, preventing
concurrent write corruption when multiple IDA instances register/unregister
simultaneously.

Uses fcntl.flock on Unix and msvcrt.locking on Windows.
Adapted from ida-multi-mcp project.
"""

from __future__ import annotations

import os
import sys
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType


class FileLockTimeout(Exception):
    """Raised when file lock acquisition times out."""
    pass


class FileLock:
    """Cross-platform file lock using context manager.

    Usage::

        with FileLock("/path/to/file.lock"):
            # exclusive access to the protected resource
            ...

    The lock file is automatically created if it doesn't exist.
    Parent directories are also created as needed.
    """

    def __init__(self, lock_path: str, timeout: float = 5.0) -> None:
        """
        Args:
            lock_path: Path to the lock file (typically ``<resource>.lock``).
            timeout: Maximum seconds to wait for lock acquisition (default 5.0).
        """
        self.lock_path = lock_path
        self.timeout = timeout
        self._fd: int | None = None

    def acquire(self) -> None:
        """Acquire the file lock, blocking until timeout."""
        parent = os.path.dirname(self.lock_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        self._fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR)

        if sys.platform == "win32":
            self._acquire_windows()
        else:
            self._acquire_unix()

    def release(self) -> None:
        """Release the file lock and close the file descriptor."""
        if self._fd is None:
            return

        if sys.platform == "win32":
            self._release_windows()
        else:
            self._release_unix()

        os.close(self._fd)
        self._fd = None

    def _acquire_unix(self) -> None:
        """Non-blocking flock with polling retry on Unix."""
        import fcntl

        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    os.close(self._fd)
                    self._fd = None
                    raise FileLockTimeout(
                        f"Could not acquire lock on {self.lock_path} "
                        f"within {self.timeout}s"
                    )
                time.sleep(0.05)

    def _release_unix(self) -> None:
        """Release flock on Unix."""
        import fcntl

        fcntl.flock(self._fd, fcntl.LOCK_UN)

    def _acquire_windows(self) -> None:
        """Non-blocking msvcrt.locking with polling retry on Windows."""
        import msvcrt

        deadline = time.monotonic() + self.timeout
        while True:
            try:
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                return
            except (OSError, IOError):
                if time.monotonic() >= deadline:
                    os.close(self._fd)
                    self._fd = None
                    raise FileLockTimeout(
                        f"Could not acquire lock on {self.lock_path} "
                        f"within {self.timeout}s"
                    )
                time.sleep(0.05)

    def _release_windows(self) -> None:
        """Release msvcrt lock on Windows."""
        import msvcrt

        try:
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        except (OSError, IOError):
            pass  # Already unlocked or lock lost

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.release()
