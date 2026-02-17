"""Centralized configuration loader for HackAgent."""
import os
import yaml
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SETTINGS = None
_TOOLS_CFG = None
_SAFETY_RULES = None


def _load_dotenv():
    """Load .env file into os.environ if it exists (does not override existing vars)."""
    env_path = _ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            if key and key not in os.environ:
                os.environ[key] = value


# Load .env on module import
_load_dotenv()


def _find_file(*candidates):
    """Return the first path that exists, or None."""
    for p in candidates:
        if p.exists():
            return p
    return None


def _apply_quality_preset(settings):
    """Apply quality preset from HACKAGENT_QUALITY env var."""
    quality = os.environ.get("HACKAGENT_QUALITY", "").lower()
    presets = settings.get("quality_presets", {})
    if quality and quality in presets:
        preset = presets[quality]
        if "model" in preset:
            settings["model_default"] = preset["model"]
        if "per_job_token_cap" in preset:
            settings["per_job_token_cap"] = preset["per_job_token_cap"]
        if "max_tokens_response" in preset:
            settings["max_tokens_response"] = preset["max_tokens_response"]
        if "temperature" in preset:
            settings["default_temperature"] = preset["temperature"]
    return settings


def load_settings():
    """Load config/settings.yaml with sensible defaults."""
    global _SETTINGS
    if _SETTINGS is not None:
        return _SETTINGS

    defaults = {
        "model_default": "claude-sonnet-4-20250514",
        "max_prompt_length": 200_000,
        "per_job_token_cap": 32_000,
        "local_tool_timeout": 30,
        "max_tokens_response": 8192,
        "default_temperature": 0.0,
    }
    path = _find_file(
        Path("/app/config/settings.yaml"),
        _ROOT / "config" / "settings.yaml",
    )
    if path:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        defaults.update(data)

    # Apply quality preset before env-var overrides
    _apply_quality_preset(defaults)

    # Allow env-var overrides (highest priority)
    if os.environ.get("HACKAGENT_MODEL"):
        defaults["model_default"] = os.environ["HACKAGENT_MODEL"]
    if os.environ.get("HACKAGENT_TOKEN_CAP"):
        defaults["per_job_token_cap"] = int(os.environ["HACKAGENT_TOKEN_CAP"])

    _SETTINGS = defaults
    return _SETTINGS


def is_pentest_mode():
    """Check if authorized pentest/bug-bounty mode is enabled."""
    return os.environ.get("HACKAGENT_PENTEST_MODE", "false").lower() == "true"


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

    # In pentest mode, add security research tools
    if is_pentest_mode():
        pentest_tools = data.get("pentest_tools", []) if path else []
        _TOOLS_CFG = list(set(_TOOLS_CFG + pentest_tools))

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
