"""Tests for core/sandbox.py — resource-limited tool execution."""
import os
import tempfile
from pathlib import Path

import pytest

from core.sandbox import run_readonly_tool


@pytest.fixture
def workdir(tmp_path):
    return str(tmp_path)


class TestRunReadonlyTool:
    def test_runs_echo(self, workdir):
        result = run_readonly_tool("echo", ["hello"], workdir)
        assert result["returncode"] == 0
        assert "hello" in result["stdout"]
        assert "timestamp" in result

    def test_missing_binary(self, workdir):
        result = run_readonly_tool("__nonexistent_tool_xyz__", [], workdir)
        assert result["error"] == "binary_not_found"

    def test_timeout(self, workdir):
        result = run_readonly_tool("sleep", ["10"], workdir, timeout=1)
        assert result["error"] == "timeout"

    def test_stdout_truncated(self, workdir):
        # Generate output longer than 8000 chars
        result = run_readonly_tool("seq", ["10000"], workdir)
        assert len(result["stdout"]) <= 8000

    def test_result_structure(self, workdir):
        result = run_readonly_tool("true", [], workdir)
        assert "tool" in result
        assert "argv" in result
        assert "returncode" in result
        assert "stdout" in result
        assert "stderr" in result
        assert "timestamp" in result

    def test_nonzero_exit(self, workdir):
        result = run_readonly_tool("false", [], workdir)
        assert result["returncode"] != 0
