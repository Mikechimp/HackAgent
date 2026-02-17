# Simple agent glue: uses router to call models and drives tasks
import json
import os
from pathlib import Path

from models.router import call_model
from core.utils import save_json, hash_prompt

LOG_DIR = Path(os.environ.get("HACKAGENT_LOG_DIR", "logs"))


def triage_job(job_meta, worker_summary):
    """Send job metadata and worker results to the AI for triage analysis."""
    prompt = (
        "SYSTEM: You are a read-only triage assistant. Return strict JSON with keys: "
        "summary (str), types_detected (list), suggested_next_steps (list), confidence (0-1), provenance (list).\n\n"
        f"JOB_META: {json.dumps(job_meta)}\n\n"
        f"WORKER_SUMMARY: {json.dumps(worker_summary, default=str)}\n\nTASK: Provide JSON only."
    )
    out = call_model(prompt, task="triage", temperature=0.0, max_tokens=800)
    # save prompts and responses for provenance
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    phash = hash_prompt(prompt)
    save_json(LOG_DIR / f"prov_{phash}_prompt.json", {"prompt": prompt})
    save_json(LOG_DIR / f"prov_{phash}_response.json", out)
    return out
