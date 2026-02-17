#!/usr/bin/env python3
"""HackAgent CLI — submit jobs, run local analysis tasks, or trigger triage."""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from tasks.recon_task import run_recon
from tasks.forensics_task import run_forensics
from core.agent import triage_job


def _data_dir():
    d = Path(os.environ.get("HACKAGENT_DATA_DIR", "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _logs_dir():
    d = Path(os.environ.get("HACKAGENT_LOG_DIR", "logs"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def submit_job(filepath, job_id=None):
    """Write a job descriptor to data/submit.json for the worker/orchestrator."""
    job_id = job_id or f"job-{int(time.time())}"
    data_dir = _data_dir()
    job = {
        "id": job_id,
        "artifact": filepath,
        "steps": [
            {"tool": "file", "args": ["-b", filepath]},
            {"tool": "strings", "args": ["-a", filepath]},
            {"tool": "xxd", "args": ["-g", "1", "-l", "512", filepath]},
        ],
        "meta": {"owner": "you", "allowed_network": False},
    }
    out_path = data_dir / "submit.json"
    with open(out_path, "w") as f:
        json.dump(job, f, indent=2)
    print(f"Job {job_id} written to {out_path}")


def run_triage(artifact):
    """Run local recon + AI triage in one shot."""
    job = {"id": f"triage-{int(time.time())}", "artifact": artifact}
    print(f"[1/3] Running recon on {artifact} ...")
    recon = run_recon(job)
    print(f"[2/3] Running forensics on {artifact} ...")
    forensics = run_forensics(job)
    print("[3/3] Sending to AI triage ...")
    worker_summary = {"recon": recon, "forensics": forensics}
    result = triage_job(job.get("meta", {}), worker_summary)
    out_path = _logs_dir() / f"{job['id']}_triage.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"Triage complete. Results saved to {out_path}")
    print(json.dumps(result, indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(
        prog="hackagent",
        description="HackAgent -- safe, analysis-only AI agent for CTFs and labs",
    )
    parser.add_argument("--submit", metavar="FILE", help="Submit artifact for worker processing")
    parser.add_argument("--recon", metavar="FILE", help="Run local recon on an artifact")
    parser.add_argument("--forensics", metavar="FILE", help="Run forensics analysis on an artifact")
    parser.add_argument("--triage", metavar="FILE", help="Full pipeline: recon + forensics + AI triage")
    parser.add_argument("--job-id", metavar="ID", help="Override auto-generated job ID")
    args = parser.parse_args()

    if not any([args.submit, args.recon, args.forensics, args.triage]):
        parser.print_help()
        sys.exit(1)

    if args.submit:
        submit_job(args.submit, job_id=args.job_id)
    if args.recon:
        result = run_recon({"id": args.job_id or "cli-recon", "artifact": args.recon})
        print(json.dumps(result, indent=2, default=str))
    if args.forensics:
        result = run_forensics({"id": args.job_id or "cli-forensics", "artifact": args.forensics})
        print(json.dumps(result, indent=2, default=str))
    if args.triage:
        run_triage(args.triage)


if __name__ == "__main__":
    main()
