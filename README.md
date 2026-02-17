# HackAgent -- Safe, Lab-Only AI Analysis Agent

This repository provides a safe, analysis-only AI agent framework to help accelerate CTFs, labs,
and lawful bug-bounty workflows. It is explicitly **not** an offensive automation framework.
Everything that could touch external networks is gated behind manual approval.

**Important:** Run this only in an isolated VM or lab environment. Snapshot the VM before use.

## Architecture

```
CLI (interfaces/cli.py)
 |
 +--> submit_job()  --> data/submit.json --> Worker container --> Orchestrator container
 |
 +--> --recon       --> tasks/recon_task.py    --> tools/file_analysis.py --> core/sandbox.py
 +--> --forensics   --> tasks/forensics_task.py --> tools/file_analysis.py --> core/sandbox.py
 +--> --triage      --> recon + forensics + AI triage via models/router.py
```

| Component | Purpose |
|-----------|---------|
| `core/sandbox.py` | Resource-limited subprocess wrapper (5 s CPU, 150 MB RAM) |
| `core/config.py` | Centralized YAML config loader with env-var overrides |
| `core/agent.py` | Glue that sends worker output to the AI for triage |
| `models/anthropic_client.py` | Claude API wrapper with budget guards and retries |
| `models/router.py` | Routes tasks to the appropriate Claude model |
| `tools/file_analysis.py` | Runs `file`, `strings`, `xxd` on artifacts |
| `tools/shell_safe.py` | Blocks network tools (`nmap`, `curl`, etc.) |
| `workers/worker.py` | Containerized tool executor with whitelist enforcement |
| `orchestrator/orchestrator.py` | Reads worker output, calls Claude, validates schema |

## Safety Controls

- **Tool whitelist**: Only `file`, `strings`, `xxd`, `hexdump`, `binwalk`, `exiftool` are allowed.
- **Blocked terms**: Prompts containing `reverse shell`, `meterpreter`, `nmap`, etc. are rejected.
- **Network gating**: Any job requesting network access requires manual `yes` confirmation.
- **Resource limits**: 5-second CPU timeout, 150 MB RAM cap per tool invocation.
- **Budget guards**: Daily token cap (200 K) and per-minute rate limit (12 req/min).
- **No code execution**: `auto_execute_generated_code` is `false` by default.
- **Container isolation**: Docker with `cap_drop: ALL` and `no-new-privileges`.

## Quickstart

### 1. Clone and set up

```bash
git clone <repo-url> && cd HackAgent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. (Optional) Set your API key

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Without an API key the tool still works -- it falls back to a local echo mode.

### 3. Run a local analysis

```bash
# Recon only
python -m interfaces.cli --recon /path/to/artifact.bin

# Forensics only
python -m interfaces.cli --forensics /path/to/artifact.bin

# Full pipeline: recon + forensics + AI triage
python -m interfaces.cli --triage /path/to/artifact.bin
```

### 4. Submit a job for container-based processing

```bash
# Write a job to data/submit.json
python -m interfaces.cli --submit /app/data/artifact.bin

# Then start the containers
docker compose up --build
```

## Docker Deployment

```bash
# Build and run both worker + orchestrator
docker compose up --build

# Or run just the worker
docker compose up worker
```

The compose file creates an **internal-only network** -- no container can reach the internet.

## Configuration

### `config/settings.yaml`

```yaml
model_default: "claude-sonnet-4-20250514"
max_prompt_length: 200000
per_job_token_cap: 8000
local_tool_timeout: 20
```

### `workers/safety_rules.yaml`

```yaml
blocked_terms:
  - "reverse shell"
  - "meterpreter"
  - "bind shell"
network_require_approval: true
auto_execute_generated_code: false
max_tool_time_seconds: 30
max_tool_memory_mb: 200
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Claude API key (optional -- local echo fallback if unset) |
| `HACKAGENT_MODEL` | Override the default model name |
| `HACKAGENT_TOKEN_CAP` | Override the per-job token cap |
| `HACKAGENT_DATA_DIR` | Override the data directory (default: `data`) |
| `HACKAGENT_LOG_DIR` | Override the log directory (default: `logs`) |

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Project Structure

```
HackAgent/
├── config/
│   ├── settings.yaml        # Model and timeout settings
│   └── tools.yaml            # Whitelisted tool names
├── core/
│   ├── agent.py              # AI triage glue
│   ├── config.py             # Centralized config loader
│   ├── sandbox.py            # Resource-limited subprocess runner
│   └── utils.py              # JSON/hash helpers
├── data/
│   └── submit.json           # Job staging file
├── interfaces/
│   └── cli.py                # Command-line interface
├── models/
│   ├── anthropic_client.py   # Claude API client with budget guards
│   └── router.py             # Task-to-model routing
├── orchestrator/
│   ├── Dockerfile
│   └── orchestrator.py       # Container-based triage orchestrator
├── tasks/
│   ├── recon_task.py          # Local artifact reconnaissance
│   └── forensics_task.py      # Timeline and binary forensics
├── tools/
│   ├── file_analysis.py       # file/strings/xxd wrappers
│   └── shell_safe.py          # Network tool blocker
├── workers/
│   ├── Dockerfile
│   ├── worker.py              # Containerized tool executor
│   ├── safety_rules.yaml      # Blocked terms and policies
│   └── tools_whitelist.json   # Allowed tool names
├── tests/
│   ├── test_sandbox.py
│   ├── test_safety.py
│   └── test_config.py
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
└── README.md
```

## License

[Eclipse Public License 2.0](LICENSE)
