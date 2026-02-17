#!/usr/bin/env python3
"""Interactive setup script for HackAgent API key and quality configuration."""
import os
import sys
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"

QUALITY_PRESETS = {
    "low": {
        "model": "claude-haiku-4-20250514",
        "token_cap": "8000",
        "description": "Fast & cheap -- good for quick recon and triage",
    },
    "standard": {
        "model": "claude-sonnet-4-20250514",
        "token_cap": "16000",
        "description": "Balanced quality and cost for general analysis",
    },
    "high": {
        "model": "claude-sonnet-4-20250514",
        "token_cap": "32000",
        "description": "Thorough analysis with higher token budgets",
    },
    "max": {
        "model": "claude-opus-4-20250514",
        "token_cap": "64000",
        "description": "Maximum quality -- Opus model, large context, deep analysis",
    },
}


def _read_env():
    """Read existing .env into a dict."""
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def _write_env(env: dict):
    """Write env dict back to .env preserving comments from example."""
    lines = []
    if ENV_EXAMPLE.exists():
        for line in ENV_EXAMPLE.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.split("=", 1)[0].strip()
                value = env.get(key, stripped.split("=", 1)[1].strip())
                lines.append(f"{key}={value}")
            else:
                lines.append(line)
    else:
        for k, v in env.items():
            lines.append(f"{k}={v}")
    ENV_FILE.write_text("\n".join(lines) + "\n")


def setup():
    print("=" * 60)
    print("  HackAgent Setup")
    print("=" * 60)
    print()

    env = _read_env()

    # --- API Key ---
    current_key = env.get("ANTHROPIC_API_KEY", "")
    masked = ""
    if current_key and current_key != "sk-ant-api03-your-key-here":
        masked = current_key[:12] + "..." + current_key[-4:]
        print(f"  Current API key: {masked}")
        change = input("  Change API key? [y/N]: ").strip().lower()
        if change != "y":
            print("  Keeping existing key.\n")
        else:
            current_key = ""

    if not current_key or current_key == "sk-ant-api03-your-key-here":
        print("  Enter your Anthropic API key.")
        print("  Get one at: https://console.anthropic.com/settings/keys")
        key = input("  API Key: ").strip()
        if not key:
            print("  No key provided. You can set ANTHROPIC_API_KEY later.")
            key = "sk-ant-api03-your-key-here"
        env["ANTHROPIC_API_KEY"] = key
        print()

    # --- Quality Preset ---
    print("  Quality presets:")
    for name, preset in QUALITY_PRESETS.items():
        marker = " <--" if env.get("HACKAGENT_QUALITY") == name else ""
        print(f"    {name:10s} | {preset['model']:40s} | {preset['description']}{marker}")
    print()
    choice = input("  Choose quality [low/standard/high/max] (default: high): ").strip().lower()
    if choice not in QUALITY_PRESETS:
        choice = "high"
    preset = QUALITY_PRESETS[choice]
    env["HACKAGENT_QUALITY"] = choice
    env["HACKAGENT_MODEL"] = preset["model"]
    env["HACKAGENT_TOKEN_CAP"] = preset["token_cap"]
    print(f"  -> Quality set to '{choice}' (model={preset['model']}, tokens={preset['token_cap']})\n")

    # --- Pentest Mode ---
    print("  Pentest / Bug-Bounty mode unlocks network recon tools.")
    print("  Only enable this for AUTHORIZED engagements.")
    pentest = input("  Enable pentest mode? [y/N]: ").strip().lower()
    env["HACKAGENT_PENTEST_MODE"] = "true" if pentest == "y" else "false"
    print()

    # --- Write ---
    _write_env(env)
    print(f"  Configuration saved to {ENV_FILE}")
    print()
    print("  To apply, run:")
    print(f"    source {ENV_FILE}  # or: export $(cat {ENV_FILE} | grep -v '^#' | xargs)")
    print()

    # Quick validation
    api_key = env.get("ANTHROPIC_API_KEY", "")
    if api_key and api_key != "sk-ant-api03-your-key-here":
        print("  Validating API key...")
        try:
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            resp = client.messages.create(
                model="claude-haiku-4-20250514",
                max_tokens=32,
                messages=[{"role": "user", "content": "Reply with exactly: OK"}],
            )
            text = resp.content[0].text if resp.content else ""
            if "OK" in text.upper():
                print("  API key is valid!\n")
            else:
                print(f"  API responded but unexpected output: {text[:80]}\n")
        except Exception as e:
            print(f"  Could not validate key: {e}")
            print("  (This may be a network issue -- the key may still be correct.)\n")
    else:
        print("  Skipping validation (no key set).\n")

    print("  Setup complete. Run 'hackagent --triage <file>' to get started.")


if __name__ == "__main__":
    setup()
