"""Task-to-model router.

Routes different analysis tasks to appropriate Claude models based on
complexity, quality settings, and task type.
"""
import os
from models.anthropic_client import call_claude_messages
from core.config import load_settings

# Model tiers
FAST_MODEL = "claude-haiku-4-20250514"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
BEST_MODEL = "claude-opus-4-20250514"

TASK_MODEL_MAP = {
    "triage": DEFAULT_MODEL,
    "decoder": FAST_MODEL,
    "forensics": DEFAULT_MODEL,
    "recon": FAST_MODEL,
    "deep_re": BEST_MODEL,
    "vuln_analysis": BEST_MODEL,
    "exploit_review": BEST_MODEL,
    "web_recon": DEFAULT_MODEL,
    "network_recon": DEFAULT_MODEL,
    "subdomain_enum": FAST_MODEL,
    "port_analysis": DEFAULT_MODEL,
    "header_analysis": DEFAULT_MODEL,
    "ssl_analysis": DEFAULT_MODEL,
}

# Max tokens per task type (higher for complex tasks)
TASK_TOKEN_MAP = {
    "triage": 4096,
    "decoder": 2048,
    "forensics": 4096,
    "recon": 2048,
    "deep_re": 8192,
    "vuln_analysis": 8192,
    "exploit_review": 8192,
    "web_recon": 4096,
    "network_recon": 4096,
    "subdomain_enum": 2048,
    "port_analysis": 4096,
    "header_analysis": 4096,
    "ssl_analysis": 4096,
}


def choose_model_for_task(task):
    """Pick the best model for the task, respecting quality settings."""
    settings = load_settings()
    override = settings.get("model_default")
    if override and override != "claude" and override != "claude-sonnet-4-20250514":
        # User explicitly set a model via quality preset -- respect tier ordering
        task_default = TASK_MODEL_MAP.get(task, DEFAULT_MODEL)
        tier = {FAST_MODEL: 0, DEFAULT_MODEL: 1, BEST_MODEL: 2}
        if tier.get(override, 1) >= tier.get(task_default, 1):
            return override
        return task_default
    return TASK_MODEL_MAP.get(task, DEFAULT_MODEL)


def choose_max_tokens(task):
    """Pick max response tokens for a task."""
    settings = load_settings()
    configured = settings.get("max_tokens_response")
    task_default = TASK_TOKEN_MAP.get(task, 4096)
    if configured and int(configured) > task_default:
        return int(configured)
    return task_default


# System prompts per task category
SYSTEM_PROMPTS = {
    "triage": (
        "You are an expert security analyst performing artifact triage. "
        "Provide thorough, structured analysis. Identify file types, embedded payloads, "
        "suspicious patterns, IOCs (indicators of compromise), and actionable next steps. "
        "Output JSON when requested, but be thorough in your analysis."
    ),
    "forensics": (
        "You are a digital forensics expert. Analyze artifacts for evidence of "
        "compromise, persistence mechanisms, lateral movement indicators, "
        "data exfiltration signs, and timeline reconstruction. Be thorough."
    ),
    "vuln_analysis": (
        "You are a vulnerability researcher. Analyze the provided data for security "
        "vulnerabilities, misconfigurations, and weaknesses. Classify findings by "
        "severity (Critical/High/Medium/Low/Info). Reference CVEs where applicable. "
        "Provide proof-of-concept guidance for authorized testing."
    ),
    "exploit_review": (
        "You are an exploit development researcher reviewing code and binaries for "
        "exploitable conditions. Identify memory corruption, logic flaws, injection "
        "points, and authentication bypasses. Provide technical detail suitable for "
        "a penetration testing report."
    ),
    "web_recon": (
        "You are a web application security expert. Analyze HTTP responses, headers, "
        "JavaScript, HTML, and API endpoints for security issues. Look for XSS, SQLI, "
        "SSRF, IDOR, authentication flaws, information disclosure, and misconfigurations."
    ),
    "network_recon": (
        "You are a network security analyst. Analyze port scans, service banners, "
        "SSL/TLS configurations, and network topology for security issues. "
        "Identify exposed services, outdated software, and attack surface."
    ),
    "default": (
        "You are a security analysis assistant for authorized penetration testing "
        "and bug bounty research. Provide thorough, actionable analysis. "
        "Output JSON when requested."
    ),
}


def call_model(prompt, task="triage", temperature=None, max_tokens=None):
    """Route a prompt to the right model and call the API."""
    settings = load_settings()
    model = choose_model_for_task(task)

    if temperature is None:
        temperature = settings.get("default_temperature", 0.0)
    if max_tokens is None:
        max_tokens = choose_max_tokens(task)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"raw": f"ECHO (local fallback -- set ANTHROPIC_API_KEY): {prompt[:1000]}"}

    system_prompt = SYSTEM_PROMPTS.get(task, SYSTEM_PROMPTS["default"])

    return call_claude_messages(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )
