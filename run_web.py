#!/usr/bin/env python3
"""Launch the HackAgent web interface.

Usage:
    python run_web.py              # Start on default port 5000
    python run_web.py --port 8080  # Start on custom port
"""
import argparse
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables from .env
from core.config import _load_dotenv
_load_dotenv()


def main():
    parser = argparse.ArgumentParser(description="HackAgent Web UI")
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("HACKAGENT_WEB_PORT", 5000)),
                        help="Port to run on (default: 5000)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--debug", action="store_true", default=True,
                        help="Run in debug mode")
    args = parser.parse_args()

    # Verify API key is set
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or api_key.startswith("sk-proj-your"):
        print("=" * 60)
        print("  WARNING: No OpenAI API key configured!")
        print("  Set OPENAI_API_KEY in your .env file")
        print("  Chat and analysis features will not work")
        print("=" * 60)
    else:
        masked = api_key[:12] + "..." + api_key[-4:]
        print(f"  OpenAI API Key: {masked}")

    print()
    print("=" * 60)
    print("  HackAgent Web UI")
    print(f"  http://{args.host}:{args.port}")
    print()
    print("  Firefox Extension endpoint:")
    print(f"  http://localhost:{args.port}/api/analyze-page")
    print("=" * 60)
    print()

    from web.app import app
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
