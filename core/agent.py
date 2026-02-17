# Agent glue: uses router to call models and drives analysis tasks
import json
import os
from pathlib import Path

from models.router import call_model
from core.utils import save_json, hash_prompt

LOG_DIR = Path(os.environ.get("HACKAGENT_LOG_DIR", "logs"))


def _log_provenance(prompt, out):
    """Save prompt/response pair for audit trail."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    phash = hash_prompt(prompt)
    save_json(LOG_DIR / f"prov_{phash}_prompt.json", {"prompt": prompt})
    save_json(LOG_DIR / f"prov_{phash}_response.json", out)


def triage_job(job_meta, worker_summary):
    """Send job metadata and worker results to the AI for triage analysis."""
    prompt = (
        "You are performing artifact triage for an authorized security engagement.\n\n"
        "Analyze the following job metadata and worker output. Provide a thorough assessment.\n\n"
        "Return strict JSON with these keys:\n"
        '- "summary" (str): detailed summary of what the artifact is and any security relevance\n'
        '- "types_detected" (list): file types, encoding schemes, packing, or obfuscation detected\n'
        '- "iocs" (list): indicators of compromise (IPs, domains, hashes, URLs, registry keys, etc.)\n'
        '- "vulnerabilities" (list): any identified vulnerabilities with severity ratings\n'
        '- "suggested_next_steps" (list): concrete next actions for the analyst\n'
        '- "confidence" (float 0-1): confidence in the analysis\n'
        '- "provenance" (list): data sources used in the analysis\n\n'
        f"JOB_META: {json.dumps(job_meta)}\n\n"
        f"WORKER_SUMMARY: {json.dumps(worker_summary, default=str)}\n\n"
        "TASK: Provide the JSON described above. Be thorough and specific."
    )
    out = call_model(prompt, task="triage")
    _log_provenance(prompt, out)
    return out


def analyze_vulnerabilities(scan_data, context=""):
    """Send scan results to AI for vulnerability analysis."""
    prompt = (
        "You are a vulnerability analyst reviewing scan results from an authorized engagement.\n\n"
        "Analyze the following data and identify all security issues.\n\n"
        "Return strict JSON with these keys:\n"
        '- "findings" (list of objects): each with "title", "severity" (Critical/High/Medium/Low/Info), '
        '"description", "evidence", "remediation", and optionally "cve"\n'
        '- "attack_surface_summary" (str): overall assessment of the attack surface\n'
        '- "priority_targets" (list): highest-value targets for further testing\n'
        '- "risk_rating" (str): overall risk level\n\n'
        f"CONTEXT: {context}\n\n"
        f"SCAN_DATA: {json.dumps(scan_data, default=str)}\n\n"
        "TASK: Provide the JSON described above."
    )
    out = call_model(prompt, task="vuln_analysis")
    _log_provenance(prompt, out)
    return out


def analyze_web_target(recon_data, context=""):
    """Send web recon data to AI for web application security analysis."""
    prompt = (
        "You are a web application security expert reviewing recon data from an authorized bug bounty.\n\n"
        "Analyze the following web recon output for vulnerabilities and misconfigurations.\n\n"
        "Return strict JSON with these keys:\n"
        '- "technologies" (list): detected web technologies and versions\n'
        '- "findings" (list of objects): each with "title", "severity", "type" (XSS/SQLI/SSRF/etc), '
        '"description", "evidence", "poc_hint"\n'
        '- "headers_analysis" (object): security header assessment\n'
        '- "attack_vectors" (list): potential attack vectors to explore\n'
        '- "next_steps" (list): recommended next testing actions\n\n'
        f"CONTEXT: {context}\n\n"
        f"RECON_DATA: {json.dumps(recon_data, default=str)}\n\n"
        "TASK: Provide the JSON described above."
    )
    out = call_model(prompt, task="web_recon")
    _log_provenance(prompt, out)
    return out


def analyze_network(recon_data, context=""):
    """Send network recon data to AI for network security analysis."""
    prompt = (
        "You are a network security analyst reviewing scan data from an authorized pentest.\n\n"
        "Analyze the following network recon output.\n\n"
        "Return strict JSON with these keys:\n"
        '- "hosts" (list): discovered hosts with open ports and services\n'
        '- "findings" (list of objects): each with "title", "severity", "host", "port", "service", "description"\n'
        '- "exposed_services" (list): services that should not be publicly accessible\n'
        '- "outdated_software" (list): services running known-vulnerable versions\n'
        '- "attack_surface" (str): overall attack surface assessment\n'
        '- "next_steps" (list): recommended next testing actions\n\n'
        f"CONTEXT: {context}\n\n"
        f"RECON_DATA: {json.dumps(recon_data, default=str)}\n\n"
        "TASK: Provide the JSON described above."
    )
    out = call_model(prompt, task="network_recon")
    _log_provenance(prompt, out)
    return out
