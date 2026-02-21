#!/usr/bin/env python3
import os, json, time, sys
from pathlib import Path
from datetime import datetime
import yaml
from models.anthropic_client import call_claude_messages
from jsonschema import validate, ValidationError

# Auto-detect project root: /app in Docker, otherwise parent of this file's directory
_DOCKER_ROOT = Path('/app')
ROOT = _DOCKER_ROOT if _DOCKER_ROOT.exists() and (_DOCKER_ROOT / 'workers').exists() else Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / 'logs'
DATA_DIR = ROOT / 'data'
POLICIES_DIR = ROOT / 'policies' if (ROOT / 'policies').exists() else ROOT / 'workers'

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
        "You are performing artifact triage for an authorized security engagement.\n\n"
        "Analyze the following job metadata and worker output. Provide thorough analysis.\n\n"
        "Return **strict JSON** with keys: summary (string), types_detected (list), "
        "iocs (list), vulnerabilities (list), suggested_next_steps (list), "
        "confidence (0-1 float), provenance (list).\n\n"
        f"JOB_META: {json.dumps(job.get('meta', {}))}\n\n"
        f"WORKER_SUMMARY: {json.dumps(excerpt)}\n\n"
        "TASK: Provide the JSON described above. Be thorough and specific."
    )

    # Call Claude if API key present; otherwise echo local fallback
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        system_msg = (
            "You are an expert security analyst performing artifact triage. "
            "Identify file types, embedded payloads, suspicious patterns, IOCs, "
            "and actionable next steps. Output strict JSON."
        )
        response = call_claude_messages(
            [{"role": "system", "content": system_msg},
             {"role": "user", "content": triage_prompt}],
            model=os.environ.get("HACKAGENT_MODEL", "claude-sonnet-4-20250514"),
            temperature=0.0,
            max_tokens=4096,
        )
        record_provenance(job_id, "triage", triage_prompt, response)
        print("Triage response written to logs.")
    else:
        # local echo fallback
        fake = {"raw": json.dumps({"summary": "Local-echo fallback: no API key set. Run 'python setup_api_key.py' to configure.", "types_detected": ["unknown"], "suggested_next_steps": ["Set ANTHROPIC_API_KEY"], "confidence": 0.1})}
        record_provenance(job_id, "triage", triage_prompt, fake)
        print("No ANTHROPIC_API_KEY found; wrote echo to logs. Run 'python setup_api_key.py' to configure.")

if __name__ == "__main__":
    run_job()
