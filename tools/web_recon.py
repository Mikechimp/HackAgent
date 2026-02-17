"""Web application reconnaissance tools for authorized bug bounty / pentest."""
from core.sandbox import run_readonly_tool
from core.config import is_pentest_mode
from tools.shell_safe import safe_shell_tool
from pathlib import Path


def http_headers(url, job_dir, timeout=30):
    """Fetch HTTP headers from a target URL (requires pentest mode)."""
    return safe_shell_tool("curl", ["-sI", "-L", "--max-time", "10", url], job_dir, timeout=timeout)


def whatweb_scan(url, job_dir, timeout=60):
    """Identify web technologies on a target."""
    return safe_shell_tool("whatweb", ["--color=never", "-a", "3", url], job_dir, timeout=timeout)


def dir_bruteforce(url, wordlist, job_dir, timeout=120):
    """Directory brute-force with gobuster (requires pentest mode)."""
    args = ["dir", "-u", url, "-w", wordlist, "-q", "--no-color", "-t", "10"]
    return safe_shell_tool("gobuster", args, job_dir, timeout=timeout)


def ffuf_fuzz(url, wordlist, job_dir, timeout=120):
    """Fuzz URL parameters or paths with ffuf."""
    args = ["-u", url, "-w", wordlist, "-mc", "200,301,302,403", "-t", "10", "-s"]
    return safe_shell_tool("ffuf", args, job_dir, timeout=timeout)


def nuclei_scan(target, job_dir, templates=None, timeout=180):
    """Run nuclei vulnerability scanner against a target."""
    args = ["-target", target, "-silent", "-nc"]
    if templates:
        args.extend(["-t", templates])
    return safe_shell_tool("nuclei", args, job_dir, timeout=timeout)


def nikto_scan(target, job_dir, timeout=180):
    """Run nikto web vulnerability scanner."""
    args = ["-h", target, "-nointeractive", "-Display", "V"]
    return safe_shell_tool("nikto", args, job_dir, timeout=timeout)


def ssl_check(host, job_dir, timeout=60):
    """Check SSL/TLS configuration of a host."""
    return safe_shell_tool("sslscan", ["--no-colour", host], job_dir, timeout=timeout)


def run_web_recon(job):
    """Run a full web recon pipeline on a target URL."""
    target = job.get("target") or job.get("artifact")
    job_id = job.get("id", "web-recon")
    job_dir = str(Path("/app/data") / job_id)
    Path(job_dir).mkdir(parents=True, exist_ok=True)

    if not is_pentest_mode():
        return {"error": "web_recon requires HACKAGENT_PENTEST_MODE=true"}

    results = []
    results.append({"phase": "headers", **http_headers(target, job_dir)})
    results.append({"phase": "whatweb", **whatweb_scan(target, job_dir)})
    results.append({"phase": "ssl", **ssl_check(target, job_dir)})

    return {"target": target, "results": results}
