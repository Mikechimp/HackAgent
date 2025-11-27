import subprocess, shutil, os, resource
from pathlib import Path
from datetime import datetime

def run_readonly_tool(tool, args, workdir, timeout=20, memory_mb=150):
    binary = shutil.which(tool)
    if not binary:
        return {"error":"binary_not_found", "tool": tool}
    argv = [binary] + args
    def preexec():
        resource.setrlimit(resource.RLIMIT_CPU, (5,5))
        resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024, memory_mb * 1024 * 1024))
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, cwd=workdir, preexec_fn=preexec, check=False)
        return {
            "tool": tool,
            "argv": argv,
            "returncode": proc.returncode,
            "stdout": proc.stdout.decode('utf-8', errors='ignore')[:8000],
            "stderr": proc.stderr.decode('utf-8', errors='ignore')[:2000],
            "timestamp": datetime.utcnow().isoformat()+"Z"
        }
    except subprocess.TimeoutExpired:
        return {"tool": tool, "error":"timeout", "timeout": timeout}
    except Exception as e:
        return {"tool": tool, "error":"exception", "exc": str(e)}
