#!/usr/bin/env python3
import os, json, time, sys
from pathlib import Path
from datetime import datetime
import yaml
from models.anthropic_client import call_claude_messages
from jsonschema import validate, ValidationError

ROOT = Path('/app')
LOG_DIR = Path('/app/logs')
DATA_DIR = Path('/app/data')
POLICIES_DIR = Path('/app/policies') if Path('/app/policies').exists() else Path('/app/workers')

# load safety rules
SAFETY = yaml.safe_load((POLICIES_DIR / 'safety_rules.yaml').read_text())

TRIAGE_SCHEMA = {
 "type":"object",
 "properties":{
   "summary":{"type":"string"},
   "types_detected":{"type":"array"},
   "suggested_next_steps":{"type":"array"},
   "confidence":{"type":"number"}
 },
 "required":["summary","types_detected"]
}

def schema_validate_triage(raw_text):
    try:
        parsed = json.loads(raw_text)
    except Exception as e:
        return False, f"json_parse_error: {e}"
    try:
        validate(instance=parsed, schema=TRIAGE_SCHEMA)
    except ValidationError as ve:
        return False, f"schema_validation_error: {ve}"
    return True, None

def requires_manual_approval(job):
    allowed = job.get('meta', {}).get('allowed_network', False)
    return allowed and SAFETY.get('network_require_approval', True)

def record_provenance(job_id, phase, prompt, response):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    p = LOG_DIR / f"{job_id}_{phase}_prompt.txt"
    r = LOG_DIR / f"{job_id}_{phase}_response.txt"
    meta = LOG_DIR / f"{job_id}_{phase}_meta.json"
    p.write_text(prompt)
    # response may be dict
    if isinstance(response, dict):
        r.write_text(response.get('raw', response.get('raw_text', str(response))))
        meta.write_text(json.dumps(response.get('meta', {}), indent=2))
    else:
        r.write_text(str(response))
        meta.write_text(json.dumps({}, indent=2))

def load_job():
    job_file = DATA_DIR / 'submit.json'
    if not job_file.exists():
        print("no job found at data/submit.json")
        return None
    return json.loads(job_file.read_text())

def run_job():
    job = load_job()
    if not job:
        return
    job_id = job.get('id', f"job-{int(time.time())}")
    if requires_manual_approval(job):
        print(f"Job {job_id} requests networked actions. Confirm (type 'yes' to allow): ", end='', flush=True)
        ans = sys.stdin.readline().strip()
        if ans.lower() != 'yes':
            print("Manual approval denied. Exiting.")
            return

    # Read worker summary if present
    summary_path = LOG_DIR / f"{job_id}_summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text())
        excerpt = summary.get('results', [])
    else:
        excerpt = [{"note":"no worker summary found"}]

    triage_prompt = (
        "SYSTEM: You are a read-only triage assistant. Output **strict JSON** following this schema: "
        "summary (string), types_detected (list), suggested_next_steps (list), confidence (0-1), provenance (list).\n\n"
        f"JOB_META: {json.dumps(job.get('meta', {}))}\n\n"
        f"WORKER_SUMMARY: {json.dumps(excerpt)}\n\n"
        "TASK: Provide the JSON described above."
    )

    # Call Claude if API key present; otherwise echo local fallback
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        response = call_claude_messages([{"role":"system","content":"You are a constrained analysis assistant. Return JSON only."},
                                         {"role":"user","content":triage_prompt}], model="claude-sonnet-4-20250514", temperature=0.0, max_tokens=800)
        record_provenance(job_id, "triage", triage_prompt, response)
        print("Triage response written to logs.")
    else:
        # local echo fallback
        fake = {"raw": json.dumps({"summary":"Local-echo fallback: no API key set","types_detected":["unknown"], "suggested_next_steps":[],"confidence":0.1})}
        record_provenance(job_id, "triage", triage_prompt, fake)
        print("No ANTHROPIC_API_KEY found; wrote echo to logs.")

if __name__ == "__main__":
    run_job()
