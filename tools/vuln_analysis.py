"""Vulnerability analysis tools -- works on local artifacts without network."""
from core.sandbox import run_readonly_tool
from tools.shell_safe import safe_shell_tool
from pathlib import Path


def search_exploitdb(query, job_dir, timeout=30):
    """Search ExploitDB using searchsploit."""
    return safe_shell_tool("searchsploit", ["--colour=no", query], job_dir, timeout=timeout)


def binary_security_check(binary_path, job_dir, timeout=30):
    """Check binary security properties (NX, PIE, RELRO, canary, etc.)."""
    results = []
    results.append({"tool": "readelf_headers", **safe_shell_tool("readelf", ["-h", binary_path], job_dir, timeout=timeout)})
    results.append({"tool": "readelf_dynamic", **safe_shell_tool("readelf", ["-d", binary_path], job_dir, timeout=timeout)})
    results.append({"tool": "readelf_symbols", **safe_shell_tool("readelf", ["-s", binary_path], job_dir, timeout=timeout)})
    results.append({"tool": "objdump_headers", **safe_shell_tool("objdump", ["-f", binary_path], job_dir, timeout=timeout)})
    return results


def hash_artifact(filepath, job_dir, timeout=10):
    """Compute SHA256 and MD5 hashes of a file."""
    results = []
    results.append(safe_shell_tool("sha256sum", [filepath], job_dir, timeout=timeout))
    results.append(safe_shell_tool("md5sum", [filepath], job_dir, timeout=timeout))
    return results


def deep_strings(filepath, job_dir, timeout=30):
    """Extract strings with context -- ASCII and Unicode, longer minimum."""
    results = []
    results.append({"encoding": "ascii", **safe_shell_tool("strings", ["-a", "-n", "6", filepath], job_dir, timeout=timeout)})
    results.append({"encoding": "unicode", **safe_shell_tool("strings", ["-a", "-el", filepath], job_dir, timeout=timeout)})
    return results


def ssl_cert_check(cert_path, job_dir, timeout=15):
    """Parse and display an X.509 certificate."""
    return safe_shell_tool("openssl", ["x509", "-in", cert_path, "-text", "-noout"], job_dir, timeout=timeout)


def run_vuln_analysis(job):
    """Run vulnerability-oriented analysis on a local artifact."""
    artifact = job.get("artifact")
    job_id = job.get("id", "vuln-analysis")
    job_dir = str(Path("/app/data") / job_id)
    Path(job_dir).mkdir(parents=True, exist_ok=True)

    results = {
        "hashes": hash_artifact(artifact, job_dir),
        "strings": deep_strings(artifact, job_dir),
        "binary_security": binary_security_check(artifact, job_dir),
    }
    return {"artifact": artifact, "results": results}
