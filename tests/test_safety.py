"""Tests for tools/shell_safe.py — tool whitelisting and pentest-mode gating."""
import pytest

from tools.shell_safe import safe_shell_tool


@pytest.fixture
def workdir(tmp_path):
    return str(tmp_path)


class TestShellSafe:
    @pytest.mark.parametrize("tool", ["nmap", "masscan", "curl", "wget", "ssh"])
    def test_pentest_tools_require_pentest_mode(self, tool, workdir):
        """Network/pentest tools are gated behind HACKAGENT_PENTEST_MODE."""
        result = safe_shell_tool(tool, [], workdir)
        assert result["error"] == "tool_requires_pentest_mode"

    def test_non_whitelisted_tool_rejected(self, workdir):
        """Tools not in the whitelist are rejected before the binary check."""
        result = safe_shell_tool("__nonexistent_xyz__", [], workdir)
        assert result["error"] == "tool_not_whitelisted"

    def test_allowed_tool_runs(self, workdir):
        """A whitelisted tool that exists on the system runs successfully."""
        result = safe_shell_tool("base64", ["--help"], workdir)
        assert result.get("error") is None
        assert result["returncode"] == 0
