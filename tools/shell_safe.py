from core.sandbox import run_readonly_tool
from core.config import is_pentest_mode, load_tools_whitelist
import shutil


# Network tools that require pentest mode
PENTEST_ONLY_TOOLS = {
    "nmap", "masscan", "curl", "wget", "ssh", "nikto", "whatweb",
    "wfuzz", "gobuster", "ffuf", "httpx", "nuclei", "sslscan",
    "sslyze", "subfinder", "amass", "dnsrecon", "hydra",
    "msfconsole", "sqlmap", "enum4linux", "smbclient", "rpcclient",
    "netcat", "hashcat", "john",
}


def safe_shell_tool(tool, args, job_dir, timeout=30):
    """Wrapper that enforces tool whitelists and pentest-mode gating."""
    whitelist = load_tools_whitelist()

    # Check if tool requires pentest mode
    if tool in PENTEST_ONLY_TOOLS and not is_pentest_mode():
        return {
            "error": "tool_requires_pentest_mode",
            "tool": tool,
            "hint": "Set HACKAGENT_PENTEST_MODE=true for authorized engagements",
        }

    # Check whitelist
    if tool not in whitelist:
        return {"error": "tool_not_whitelisted", "tool": tool}

    if shutil.which(tool) is None:
        return {"error": "binary_not_found", "tool": tool}

    return run_readonly_tool(tool, args, job_dir, timeout=timeout)
