"""Tests for core/utils.py — JSON and hashing helpers."""
import json
from pathlib import Path

from core.utils import save_json, hash_prompt


class TestSaveJson:
    def test_creates_file(self, tmp_path):
        p = tmp_path / "out.json"
        save_json(p, {"key": "value"})
        assert p.exists()
        assert json.loads(p.read_text()) == {"key": "value"}

    def test_creates_parent_dirs(self, tmp_path):
        p = tmp_path / "a" / "b" / "out.json"
        save_json(p, [1, 2, 3])
        assert p.exists()
        assert json.loads(p.read_text()) == [1, 2, 3]


class TestHashPrompt:
    def test_returns_string(self):
        h = hash_prompt("test prompt")
        assert isinstance(h, str)

    def test_consistent(self):
        assert hash_prompt("abc") == hash_prompt("abc")

    def test_different_inputs(self):
        assert hash_prompt("hello") != hash_prompt("world")

    def test_length(self):
        assert len(hash_prompt("x")) == 12
