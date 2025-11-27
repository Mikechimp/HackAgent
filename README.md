# AI Agent Lab (Safe, Lab-Only)

This repository provides a safe, analysis-only AI agent skeleton to help accelerate CTFs, labs,
and lawful bug-bounty workflows. It is explicitly **not** an offensive automation framework.
Everything that could touch external networks is gated behind manual approval.

**Important:** Run this only in an isolated VM or lab environment. Snapshot the VM before use.

## Quickstart (dev on VSCode, deploy to Kali/Ubuntu VM)

1. Copy repo to your development machine and open in VSCode.
2. Install Python dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
