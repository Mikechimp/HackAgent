#!/usr/bin/env python3
import argparse, json, os
from tasks.recon_task import run_recon
from tasks.forensics_task import run_forensics
from pathlib import Path

def submit_job(filepath, job_id=None):
    job_id = job_id or f"job-{int(__import__('time').time())}"
    data_dir = Path('/app/data')
    data_dir.mkdir(parents=True, exist_ok=True)
    # copy or reference artifact (we assume file is already inside /app/data or mounted)
    job = {
        "id": job_id,
        "artifact": filepath,
        "steps": [],
        "meta": {"owner":"you", "allowed_network": False}
    }
    with open(data_dir / 'submit.json', 'w') as f:
        json.dump(job, f, indent=2)
    print(f"Job {job_id} written to data/submit.json")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--submit', help='submit artifact path inside data dir', required=False)
    parser.add_argument('--recon', help='run recon on artifact using local task', required=False)
    parser.add_argument('--forensics', help='run forensics on artifact', required=False)
    args = parser.parse_args()
    if args.submit:
        submit_job(args.submit)
    if args.recon:
        run_recon({"id": "cli-recon", "artifact": args.recon})
    if args.forensics:
        run_forensics({"id":"cli-forens", "artifact": args.forensics})

if __name__ == "__main__":
    main()
