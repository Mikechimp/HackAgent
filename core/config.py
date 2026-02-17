"""Centralized configuration loader for HackAgent."""
import os
import yaml
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SETTINGS = None
_TOOLS_CFG = None
_SAFETY_RULES = None


def _find_file(*candidates):
    """Return the first path that exists, or None."""
    for p in candidates:
        if p.exists():
            return p
    return None


def load_settings():
    """Load config/settings.yaml with sensible defaults."""
    global _SETTINGS
    if _SETTINGS is not None:
        return _SETTINGS

    defaults = {
        "model_default": "claude-sonnet-4-20250514",
        "max_prompt_length": 200_000,
        "per_job_token_cap": 8_000,
        "local_tool_timeout": 20,
    }
    path = _find_file(
        Path("/app/config/settings.yaml"),
        _ROOT / "config" / "settings.yaml",
    )
    if path:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        defaults.update(data)

    # Allow env-var overrides
    if os.environ.get("HACKAGENT_MODEL"):
        defaults["model_default"] = os.environ["HACKAGENT_MODEL"]
    if os.environ.get("HACKAGENT_TOKEN_CAP"):
        defaults["per_job_token_cap"] = int(os.environ["HACKAGENT_TOKEN_CAP"])

    _SETTINGS = defaults
    return _SETTINGS


def load_tools_whitelist():
    """Load the whitelisted tool names from config/tools.yaml."""
    global _TOOLS_CFG
    if _TOOLS_CFG is not None:
        return _TOOLS_CFG

    path = _find_file(
        Path("/app/config/tools.yaml"),
        _ROOT / "config" / "tools.yaml",
    )
    if path:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        _TOOLS_CFG = data.get("whitelisted_tools", [])
    else:
        _TOOLS_CFG = ["file", "strings", "xxd", "hexdump", "binwalk", "exiftool"]
    return _TOOLS_CFG


def load_safety_rules():
    """Load workers/safety_rules.yaml."""
    global _SAFETY_RULES
    if _SAFETY_RULES is not None:
        return _SAFETY_RULES

    path = _find_file(
        Path("/app/policies/safety_rules.yaml"),
        Path("/app/workers/safety_rules.yaml"),
        _ROOT / "workers" / "safety_rules.yaml",
    )
    if path:
        with open(path) as f:
            _SAFETY_RULES = yaml.safe_load(f) or {}
    else:
        _SAFETY_RULES = {
            "blocked_terms": [],
            "network_require_approval": True,
            "auto_execute_generated_code": False,
            "max_tool_time_seconds": 30,
            "max_tool_memory_mb": 200,
        }
    return _SAFETY_RULES
