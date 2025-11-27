import json, hashlib, os
from pathlib import Path

def save_json(path, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(obj, f, indent=2)

def hash_prompt(prompt):
    return hashlib.sha256(prompt.encode('utf-8')).hexdigest()[:12]
