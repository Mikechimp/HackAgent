#!/usr/bin/env python3
import json, shutil, subprocess, time, os, resource
from pathlib import Path
from datetime import datetime

# Auto-detect project root: /app in Docker, otherwise parent of this file's directory
_DOCKER_ROOT = Path('/app')
ROOT = _DOCKER_ROOT if _DOCKER_ROOT.exists() and (_DOCKER_ROOT / 'workers').exists() else Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / 'logs'
DATA_DIR = ROOT / 'data'
WHITELIST = json.loads((Path(__file__).parent / 'tools_whitelist.json').read_text())

CMD_TIMEOUT = int(os.environ.get("WORKER_TOOL_TIMEOUT", "20"))

def safe_run_tool(tool, args, job_id, job_dir):
    if tool not in WHITELIST:
        return {'error': 'tool_not_whitelisted', 'tool': tool}
    binary = shutil.which(tool)
    if not binary:
        return {'error': 'binary_not_found', 'tool': tool}
    argv = [binary] + args
    def preexec():
        resource.setrlimit(resource.RLIMIT_CPU, (5,5))
        resource.setrlimit(resource.RLIMIT_AS, (150 * 1024 * 1024, 150 * 1024 * 1024))
        try:
            os.setgid(1000); os.setuid(1000)
        except Exception:
            pass
    start = time.time()
    try:
        proc = subprocess.run(argv,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              cwd=job_dir,
                              timeout=CMD_TIMEOUT,
                              preexec_fn=preexec,
                              check=False)
        elapsed = time.time() - start
        out = proc.stdout.decode('utf-8', errors='ignore')
        err = proc.stderr.decode('utf-8', errors='ignore')
        record = {
            'tool': tool,
            'argv': argv,
            'returncode': proc.returncode,
            'stdout_preview': out[:4000],
            'stderr_preview': err[:1000],
            'elapsed': elapsed,
            'timestamp': datetime.utcnow().isoformat()+'Z'
        }
    except subprocess.TimeoutExpired:
        record = {'tool': tool, 'error': 'timeout', 'timeout': CMD_TIMEOUT}
    except Exception as e:
        record = {'tool': tool, 'error': 'exception', 'exc': str(e)}
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_DIR / f"{job_id}_{tool}.json", 'w') as f:
        json.dump(record, f, indent=2)
    return record

def load_job():
    job_file = DATA_DIR / 'submit.json'
    if not job_file.exists():
        print("no job found at data/submit.json; drop one in and restart")
        return None
    return json.loads(job_file.read_text())

def main():
    job = load_job()
    if not job:
        return
    job_id = job.get('id', f'job-{int(time.time())}')
    job_dir = DATA_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    steps = job.get('steps', [])
    results = []
    for step in steps:
        tool = step.get('tool')
        args = step.get('args', [])
        res = safe_run_tool(tool, args, job_id, str(job_dir))
        results.append(res)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_DIR / f"{job_id}_summary.json", 'w') as f:
        json.dump({'job_id': job_id, 'results': results}, f, indent=2)
    print(json.dumps({'status': 'done', 'job_id': job_id}, indent=2))

if __name__ == "__main__":
    main()
