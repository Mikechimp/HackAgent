from core.sandbox import run_readonly_tool
from pathlib import Path

def analyze_file(path, job_dir):
    out = []
    out.append(run_readonly_tool("file", ["-b", str(path)], job_dir))
    out.append(run_readonly_tool("strings", ["-a", str(path)], job_dir))
    out.append(run_readonly_tool("xxd", ["-g", "1", "-l", "512", str(path)], job_dir))
    return out
