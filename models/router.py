"""Task-to-model router.

Routes different analysis tasks to appropriate Claude models based on
complexity and cost considerations.
"""
import os
from models.anthropic_client import call_claude_messages
from core.config import load_settings

# Model tiers
FAST_MODEL = "claude-haiku-4-20250514"
DEFAULT_MODEL = "claude-sonnet-4-20250514"

TASK_MODEL_MAP = {
    "triage": DEFAULT_MODEL,
    "decoder": FAST_MODEL,
    "forensics": DEFAULT_MODEL,
    "recon": FAST_MODEL,
    "deep_re": DEFAULT_MODEL,
}


def choose_model_for_task(task):
    """Pick the cheapest model that can handle the task well."""
    settings = load_settings()
    override = settings.get("model_default")
    if override and override != "claude":
        return override
    return TASK_MODEL_MAP.get(task, DEFAULT_MODEL)


def call_model(prompt, task="triage", temperature=0.0, max_tokens=800):
    """Route a prompt to the right model and call the API."""
    model = choose_model_for_task(task)
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"raw": f"ECHO (local fallback): {prompt[:1000]}"}
    return call_claude_messages(
        [
            {"role": "system", "content": "You are a constrained analysis assistant. Output JSON only when requested."},
            {"role": "user", "content": prompt},
        ],
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )
