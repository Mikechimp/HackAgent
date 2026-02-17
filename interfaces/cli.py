#!/usr/bin/env python3
"""HackAgent CLI — submit jobs, run local analysis tasks, or trigger triage.

Supports bug bounty and penetration testing workflows when
HACKAGENT_PENTEST_MODE=true is set.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from tasks.recon_task import run_recon
from tasks.forensics_task import run_forensics
from core.agent import triage_job, analyze_vulnerabilities, analyze_web_target, analyze_network
from core.config import is_pentest_mode, load_settings


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


def run_vuln_scan(artifact):
    """Run vulnerability analysis on a local artifact."""
    from tools.vuln_analysis import run_vuln_analysis
    job = {"id": f"vuln-{int(time.time())}", "artifact": artifact}
    print(f"[1/2] Running vulnerability analysis on {artifact} ...")
    scan_data = run_vuln_analysis(job)
    print("[2/2] Sending to AI for vulnerability assessment ...")
    result = analyze_vulnerabilities(scan_data, context=f"Artifact: {artifact}")
    out_path = _logs_dir() / f"{job['id']}_vuln.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"Vulnerability analysis complete. Results saved to {out_path}")
    print(json.dumps(result, indent=2, default=str))


def run_web_scan(target):
    """Run web reconnaissance on a target URL (requires pentest mode)."""
    if not is_pentest_mode():
        print("Error: Web scanning requires HACKAGENT_PENTEST_MODE=true")
        print("Set this in your .env file or environment for authorized engagements.")
        sys.exit(1)
    from tools.web_recon import run_web_recon
    job = {"id": f"web-{int(time.time())}", "target": target}
    print(f"[1/2] Running web recon on {target} ...")
    recon_data = run_web_recon(job)
    print("[2/2] Sending to AI for web security analysis ...")
    result = analyze_web_target(recon_data, context=f"Target: {target}")
    out_path = _logs_dir() / f"{job['id']}_web.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"Web analysis complete. Results saved to {out_path}")
    print(json.dumps(result, indent=2, default=str))


def run_net_scan(target):
    """Run network reconnaissance on a target (requires pentest mode)."""
    if not is_pentest_mode():
        print("Error: Network scanning requires HACKAGENT_PENTEST_MODE=true")
        print("Set this in your .env file or environment for authorized engagements.")
        sys.exit(1)
    from tools.network_recon import run_network_recon
    job = {"id": f"net-{int(time.time())}", "target": target}
    print(f"[1/2] Running network recon on {target} ...")
    recon_data = run_network_recon(job)
    print("[2/2] Sending to AI for network security analysis ...")
    result = analyze_network(recon_data, context=f"Target: {target}")
    out_path = _logs_dir() / f"{job['id']}_net.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"Network analysis complete. Results saved to {out_path}")
    print(json.dumps(result, indent=2, default=str))


def show_config():
    """Display current configuration."""
    settings = load_settings()
    pentest = is_pentest_mode()
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    masked_key = (api_key[:12] + "..." + api_key[-4:]) if len(api_key) > 16 else "(not set)"
    print("HackAgent Configuration")
    print("=" * 40)
    print(f"  API Key:       {masked_key}")
    print(f"  Model:         {settings.get('model_default')}")
    print(f"  Quality:       {os.environ.get('HACKAGENT_QUALITY', 'default')}")
    print(f"  Token Cap:     {settings.get('per_job_token_cap')}")
    print(f"  Max Response:  {settings.get('max_tokens_response')}")
    print(f"  Pentest Mode:  {'ENABLED' if pentest else 'disabled'}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="hackagent",
        description="HackAgent -- AI-powered security analysis for CTFs, bug bounty, and authorized pentests",
    )
    parser.add_argument("--submit", metavar="FILE", help="Submit artifact for worker processing")
    parser.add_argument("--recon", metavar="FILE", help="Run local recon on an artifact")
    parser.add_argument("--forensics", metavar="FILE", help="Run forensics analysis on an artifact")
    parser.add_argument("--triage", metavar="FILE", help="Full pipeline: recon + forensics + AI triage")
    parser.add_argument("--vuln", metavar="FILE", help="Run vulnerability analysis on a local artifact")
    parser.add_argument("--web-scan", metavar="URL", help="Web application recon (requires pentest mode)")
    parser.add_argument("--net-scan", metavar="TARGET", help="Network recon (requires pentest mode)")
    parser.add_argument("--config", action="store_true", help="Show current configuration")
    parser.add_argument("--setup", action="store_true", help="Run interactive setup")
    parser.add_argument("--job-id", metavar="ID", help="Override auto-generated job ID")
    args = parser.parse_args()

    if args.config:
        show_config()
        return

    if args.setup:
        from setup_api_key import setup
        setup()
        return

    if not any([args.submit, args.recon, args.forensics, args.triage,
                args.vuln, args.web_scan, args.net_scan]):
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
    if args.vuln:
        run_vuln_scan(args.vuln)
    if args.web_scan:
        run_web_scan(args.web_scan)
    if args.net_scan:
        run_net_scan(args.net_scan)


if __name__ == "__main__":
    main()
