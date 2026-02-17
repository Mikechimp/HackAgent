"""Tests for tools/shell_safe.py — network tool blocking."""
import pytest

from tools.shell_safe import safe_shell_tool


@pytest.fixture
def workdir(tmp_path):
    return str(tmp_path)


class TestShellSafe:
    @pytest.mark.parametrize("tool", ["nmap", "masscan", "curl", "wget", "ssh"])
    def test_blocked_tools(self, tool, workdir):
        result = safe_shell_tool(tool, [], workdir)
        assert result["error"] == "tool_blocked_for_network"

    def test_missing_binary(self, workdir):
        result = safe_shell_tool("__nonexistent_xyz__", [], workdir)
        assert result["error"] == "binary_not_found"

    def test_allowed_tool_runs(self, workdir):
        result = safe_shell_tool("echo", ["safe"], workdir)
        assert result.get("error") is None
        assert result["returncode"] == 0
        assert "safe" in result["stdout"]
