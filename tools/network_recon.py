"""Network reconnaissance tools for authorized pentest / bug bounty."""
from core.sandbox import run_readonly_tool
from core.config import is_pentest_mode
from tools.shell_safe import safe_shell_tool
from pathlib import Path


def nmap_scan(target, job_dir, ports=None, scan_type="-sV", timeout=180):
    """Run nmap service version scan (requires pentest mode)."""
    args = [scan_type, "--open", "-T4"]
    if ports:
        args.extend(["-p", ports])
    args.append(target)
    return safe_shell_tool("nmap", args, job_dir, timeout=timeout)


def dns_lookup(domain, job_dir, record_type="ANY", timeout=30):
    """DNS record lookup."""
    return safe_shell_tool("dig", [domain, record_type, "+noall", "+answer"], job_dir, timeout=timeout)


def whois_lookup(target, job_dir, timeout=30):
    """WHOIS lookup for a domain or IP."""
    return safe_shell_tool("whois", [target], job_dir, timeout=timeout)


def traceroute_target(target, job_dir, timeout=60):
    """Trace network path to a target."""
    return safe_shell_tool("traceroute", ["-m", "20", target], job_dir, timeout=timeout)


def subdomain_enum(domain, job_dir, timeout=120):
    """Enumerate subdomains using subfinder."""
    return safe_shell_tool("subfinder", ["-d", domain, "-silent"], job_dir, timeout=timeout)


def masscan_sweep(target, ports, job_dir, timeout=120):
    """Fast port sweep with masscan."""
    args = ["-p", ports, "--rate", "1000", target]
    return safe_shell_tool("masscan", args, job_dir, timeout=timeout)


def run_network_recon(job):
    """Run a full network recon pipeline on a target."""
    target = job.get("target") or job.get("artifact")
    job_id = job.get("id", "net-recon")
    job_dir = str(Path("/app/data") / job_id)
    Path(job_dir).mkdir(parents=True, exist_ok=True)

    if not is_pentest_mode():
        return {"error": "network_recon requires HACKAGENT_PENTEST_MODE=true"}

    results = []
    results.append({"phase": "dns", **dns_lookup(target, job_dir)})
    results.append({"phase": "whois", **whois_lookup(target, job_dir)})
    results.append({"phase": "nmap_top1000", **nmap_scan(target, job_dir)})

    return {"target": target, "results": results}
