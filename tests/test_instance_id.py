"""Tests for instance_id.py — ID generation and collision resolution."""

import pytest

from ida_pro_mcp.instance_id import (
    BASE36_CHARS,
    DEFAULT_ID_LENGTH,
    generate_instance_id,
    resolve_collision,
)


class TestGenerateInstanceId:
    def test_deterministic_output(self):
        """Same inputs always produce the same ID."""
        id1 = generate_instance_id(123, 4567, "/tmp/test.i64")
        id2 = generate_instance_id(123, 4567, "/tmp/test.i64")
        assert id1 == id2

    def test_correct_length(self):
        """Default output is 4 characters."""
        result = generate_instance_id(1, 2, "x")
        assert len(result) == DEFAULT_ID_LENGTH

    def test_base36_charset(self):
        """All characters are valid base36."""
        result = generate_instance_id(999, 8080, "/some/path.i64")
        for ch in result:
            assert ch in BASE36_CHARS

    def test_different_inputs_produce_different_ids(self):
        """Different pid/port/path combos yield different IDs."""
        id_a = generate_instance_id(1, 100, "/a.i64")
        id_b = generate_instance_id(2, 200, "/b.i64")
        assert id_a != id_b

    def test_custom_length(self):
        """Explicit length parameter changes output size."""
        result = generate_instance_id(1, 2, "x", length=7)
        assert len(result) == 7

    def test_length_one(self):
        """Edge case: length=1 produces a single base36 char."""
        result = generate_instance_id(42, 9999, "/test.i64", length=1)
        assert len(result) == 1
        assert result in BASE36_CHARS

    def test_different_pid_same_port_path(self):
        """Different PIDs with same port/path produce different IDs."""
        id_a = generate_instance_id(100, 5000, "/test.i64")
        id_b = generate_instance_id(200, 5000, "/test.i64")
        assert id_a != id_b

    def test_different_port_same_pid_path(self):
        """Different ports with same PID/path produce different IDs."""
        id_a = generate_instance_id(100, 5000, "/test.i64")
        id_b = generate_instance_id(100, 6000, "/test.i64")
        assert id_a != id_b

    def test_different_path_same_pid_port(self):
        """Different paths with same PID/port produce different IDs."""
        id_a = generate_instance_id(100, 5000, "/a.i64")
        id_b = generate_instance_id(100, 5000, "/b.i64")
        assert id_a != id_b


class TestResolveCollision:
    def test_no_collision_passthrough(self):
        """When no collision, returns the original candidate."""
        candidate = generate_instance_id(1, 2, "x")
        result = resolve_collision(candidate, set(), 1, 2, "x")
        assert result == candidate

    def test_collision_expands_to_five_chars(self):
        """On collision, expands to 5-char ID."""
        candidate = generate_instance_id(1, 2, "x")
        result = resolve_collision(candidate, {candidate}, 1, 2, "x")
        assert result != candidate
        assert len(result) == DEFAULT_ID_LENGTH + 1

    def test_suffix_fallback(self):
        """When both 4-char and 5-char collide, falls back to suffix."""
        candidate = generate_instance_id(1, 2, "x")
        expanded = generate_instance_id(1, 2, "x", length=5)
        existing = {candidate, expanded}
        result = resolve_collision(candidate, existing, 1, 2, "x")
        assert result not in existing
        assert len(result) == DEFAULT_ID_LENGTH + 1  # candidate + 1 suffix char

    def test_runtime_error_when_exhausted(self):
        """RuntimeError when all suffix combinations are taken."""
        candidate = generate_instance_id(1, 2, "x")
        expanded = generate_instance_id(1, 2, "x", length=5)
        # Block all 1-char suffixes (36) and all 2-char suffixes (1296)
        all_suffixed_1 = {candidate + ch for ch in BASE36_CHARS}
        all_suffixed_2 = {
            candidate + c1 + c2
            for c1 in BASE36_CHARS
            for c2 in BASE36_CHARS
        }
        existing = {candidate, expanded} | all_suffixed_1 | all_suffixed_2
        with pytest.raises(RuntimeError, match="Cannot generate unique"):
            resolve_collision(candidate, existing, 1, 2, "x")

    def test_empty_existing_set(self):
        """Empty existing set always returns candidate unchanged."""
        candidate = generate_instance_id(42, 8080, "/bin.i64")
        result = resolve_collision(candidate, set(), 42, 8080, "/bin.i64")
        assert result == candidate
