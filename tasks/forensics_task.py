# Forensics task: simple timeline + extraction helpers
from tools.file_analysis import analyze_file
from core.utils import save_json
from pathlib import Path

def run_forensics(job):
    job_id = job.get('id')
    artifact = job.get('artifact')
    job_dir = Path('/app/data') / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    results = analyze_file(artifact, str(job_dir))
    # basic timeline: lengths, magic, first strings preview
    timeline = {
        "artifact": artifact,
        "size": None,
        "magic": results[0].get('stdout') if results and results[0] else None,
        "strings_preview": (results[1].get('stdout')[:2000]) if results and results[1] else ""
    }
    save_json(Path('/app/logs') / f"{job_id}_forensics.json", timeline)
    return timeline
