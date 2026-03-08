"""Tests for filelock.py — Cross-platform file locking."""

import os
import threading
import time

import pytest

from ida_pro_mcp.filelock import FileLock, FileLockTimeout


class TestFileLockBasic:
    def test_context_manager_creates_lock_file(self, tmp_path):
        """Lock file is created when acquired via context manager."""
        lock_path = str(tmp_path / "test.lock")
        with FileLock(lock_path):
            assert os.path.exists(lock_path)

    def test_creates_parent_directories(self, tmp_path):
        """Lock file creation also creates parent directories."""
        lock_path = str(tmp_path / "deep" / "nested" / "test.lock")
        with FileLock(lock_path):
            assert os.path.exists(lock_path)

    def test_acquire_and_release(self, tmp_path):
        """Manual acquire/release cycle works."""
        lock_path = str(tmp_path / "manual.lock")
        lock = FileLock(lock_path)
        lock.acquire()
        assert lock._fd is not None
        lock.release()
        assert lock._fd is None

    def test_release_without_acquire_is_safe(self, tmp_path):
        """Calling release without acquire does not raise."""
        lock = FileLock(str(tmp_path / "noop.lock"))
        lock.release()  # Should not raise

    def test_double_release_is_safe(self, tmp_path):
        """Calling release twice does not raise."""
        lock_path = str(tmp_path / "double.lock")
        lock = FileLock(lock_path)
        lock.acquire()
        lock.release()
        lock.release()  # Should not raise


class TestFileLockMutualExclusion:
    def test_concurrent_lock_serializes_access(self, tmp_path):
        """Two threads cannot hold the same lock simultaneously."""
        lock_path = str(tmp_path / "mutex.lock")
        results = []
        barrier = threading.Barrier(2)

        def worker(thread_id):
            barrier.wait(timeout=5)
            with FileLock(lock_path, timeout=10.0):
                results.append(f"enter-{thread_id}")
                time.sleep(0.05)  # Hold lock briefly
                results.append(f"exit-{thread_id}")

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join(timeout=20)
        t2.join(timeout=20)

        # Verify serialization: entries should not interleave
        assert len(results) == 4
        # Find enter/exit pairs
        first_enter = results[0]
        first_exit = results[1]
        tid = first_enter.split("-")[1]
        assert first_exit == f"exit-{tid}", "Lock was not held exclusively"


class TestFileLockTimeout:
    def test_timeout_raises(self, tmp_path):
        """Timeout raises FileLockTimeout when lock is held."""
        lock_path = str(tmp_path / "timeout.lock")
        lock1 = FileLock(lock_path, timeout=10.0)
        lock1.acquire()

        try:
            lock2 = FileLock(lock_path, timeout=0.1)
            with pytest.raises(FileLockTimeout):
                lock2.acquire()
        finally:
            lock1.release()
