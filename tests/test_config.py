"""Tests for core/config.py — configuration loading."""
import os
import pytest

# Reset cached state before each test
import core.config as config_mod


@pytest.fixture(autouse=True)
def _reset_config_cache():
    config_mod._SETTINGS = None
    config_mod._TOOLS_CFG = None
    config_mod._SAFETY_RULES = None
    yield
    config_mod._SETTINGS = None
    config_mod._TOOLS_CFG = None
    config_mod._SAFETY_RULES = None


class TestLoadSettings:
    def test_returns_dict(self):
        settings = config_mod.load_settings()
        assert isinstance(settings, dict)

    def test_has_required_keys(self):
        settings = config_mod.load_settings()
        assert "max_prompt_length" in settings
        assert "per_job_token_cap" in settings
        assert "local_tool_timeout" in settings

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("HACKAGENT_MODEL", "test-model-123")
        settings = config_mod.load_settings()
        assert settings["model_default"] == "test-model-123"

    def test_caching(self):
        s1 = config_mod.load_settings()
        s2 = config_mod.load_settings()
        assert s1 is s2


class TestLoadToolsWhitelist:
    def test_returns_list(self):
        tools = config_mod.load_tools_whitelist()
        assert isinstance(tools, list)

    def test_contains_core_tools(self):
        tools = config_mod.load_tools_whitelist()
        for t in ["file", "strings", "xxd"]:
            assert t in tools


class TestLoadSafetyRules:
    def test_returns_dict(self):
        rules = config_mod.load_safety_rules()
        assert isinstance(rules, dict)

    def test_has_blocked_terms(self):
        rules = config_mod.load_safety_rules()
        assert "blocked_terms" in rules
        assert len(rules["blocked_terms"]) > 0

    def test_network_approval_required(self):
        rules = config_mod.load_safety_rules()
        assert rules["network_require_approval"] is True

    def test_no_auto_execute(self):
        rules = config_mod.load_safety_rules()
        assert rules["auto_execute_generated_code"] is False
