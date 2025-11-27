import os
from models.anthropic_client import call_claude_messages

def choose_model_for_task(task):
    # Very simple router: triage -> local/claude low cost; deep RE -> claude
    if task in ("triage", "decoder", "forensics"):
        return "claude-3.7-sonnet"
    return "claude-3.7-sonnet"

def call_model(prompt, task="triage", temperature=0.0, max_tokens=800):
    model = choose_model_for_task(task)
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"raw": f"ECHO (local fallback): {prompt[:1000]}"}
    return call_claude_messages([{"role":"system","content":"You are a constrained analysis assistant. Output JSON only when requested."},
                                 {"role":"user","content":prompt}], model=model, temperature=temperature, max_tokens_to_sample=max_tokens)
