from core.sandbox import run_readonly_tool
import shutil

def safe_shell_tool(tool, args, job_dir):
    # Wrapper that refuses network tools by name.
    blocked = ["nmap", "masscan", "curl", "wget", "ssh"]
    if tool in blocked:
        return {"error":"tool_blocked_for_network", "tool": tool}
    if shutil.which(tool) is None:
        return {"error":"binary_not_found", "tool": tool}
    return run_readonly_tool(tool, args, job_dir)
