# Recon task: reads local artifacts and returns parsed outputs (no scanning)
from tools.file_analysis import analyze_file
from core.utils import save_json
from pathlib import Path

def run_recon(job):
    job_id = job.get('id')
    artifact = job.get('artifact')
    job_dir = Path('/app/data') / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    results = analyze_file(artifact, str(job_dir))
    save_json(Path('/app/logs') / f"{job_id}_recon.json", results)
    return results
