"""HackAgent Web Interface — Flask backend with Arabic-inspired dark theme.

Serves the chat UI and provides API endpoints for:
- Chat with HackAgent AI personality
- URL analysis for vulnerability detection
- Page content analysis (from Firefox extension)
- Screenshot analysis via GPT-4 Vision
"""
import os
import sys
import json
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS

from core.config import load_settings, _load_dotenv
from core.page_analyzer import fetch_page, quick_vuln_check
from models.openai_client import (
    chat_with_hackagent,
    analyze_page_with_vision,
    analyze_url_content,
)


def _check_api_key():
    """Return an error message if the OpenAI API key is missing/placeholder, else None."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key or api_key.startswith("sk-proj-your"):
        return (
            "No OpenAI API key configured. "
            "Add your key to the .env file: OPENAI_API_KEY=sk-proj-..."
        )
    return None

# Load .env before anything else
_load_dotenv()

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("hackagent_web")

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)
app.secret_key = os.environ.get("HACKAGENT_SECRET_KEY", "hackagent-dev-secret")

# Enable CORS for Firefox extension
CORS(app, resources={r"/api/*": {"origins": "*"}})

# In-memory conversation storage (per session)
conversations = {}

# Load attack surface knowledge base
ATTACK_SURFACE_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_surface.json"
attack_surface_db = {}
if ATTACK_SURFACE_PATH.exists():
    with open(ATTACK_SURFACE_PATH) as f:
        attack_surface_db = json.load(f)


@app.route("/")
def index():
    """Serve the main HackAgent chat interface."""
    return render_template("index.html")


@app.route("/api/chat", methods=["POST"])
def api_chat():
    """Chat with the HackAgent AI personality."""
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Missing 'message' field"}), 400

    key_err = _check_api_key()
    if key_err:
        return jsonify({"error": key_err}), 503

    user_message = data["message"]
    session_id = data.get("session_id", "default")
    model = data.get("model", "gpt-4o")

    # Get or create conversation history
    if session_id not in conversations:
        conversations[session_id] = []

    history = conversations[session_id]

    try:
        result = chat_with_hackagent(user_message, conversation_history=history, model=model)

        # Update conversation history
        history.append({"role": "user", "content": user_message})
        history.append({"role": "assistant", "content": result["raw_text"]})

        # Keep only last 20 messages to manage context
        if len(history) > 20:
            conversations[session_id] = history[-20:]

        return jsonify({
            "response": result["raw_text"],
            "tokens": result.get("tokens_estimated", 0),
            "model": result.get("meta", {}).get("model", model),
        })

    except Exception as e:
        LOG.error(f"Chat error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():
    """Analyze a URL for security vulnerabilities."""
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field"}), 400

    key_err = _check_api_key()
    if key_err:
        return jsonify({"error": key_err}), 503

    url = data["url"]
    LOG.info(f"Analyzing URL: {url}")

    try:
        # Step 1: Fetch and parse the page
        page_data = fetch_page(url)

        # Step 2: Run quick automated checks
        quick_findings = quick_vuln_check(page_data)

        # Step 3: Send to AI for deep analysis
        ai_result = analyze_url_content(
            url=url,
            headers=page_data.get("headers", {}),
            html=page_data.get("html", ""),
            scripts=page_data.get("scripts", []),
            forms=page_data.get("forms", []),
            cookies=page_data.get("cookies", []),
        )

        # Step 4: Cross-reference with attack surface DB
        matched_tech = _match_attack_surface(page_data.get("technologies", []))

        return jsonify({
            "url": url,
            "status_code": page_data.get("status_code"),
            "technologies": page_data.get("technologies", []),
            "security_headers": page_data.get("security_headers", {}),
            "quick_findings": quick_findings,
            "ai_analysis": ai_result.get("raw_text", ""),
            "attack_surface_matches": matched_tech,
            "forms_count": len(page_data.get("forms", [])),
            "scripts_count": len(page_data.get("scripts", [])),
            "comments_count": len(page_data.get("comments", [])),
            "errors": page_data.get("errors", []),
        })

    except Exception as e:
        LOG.error(f"URL analysis error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze-page", methods=["POST"])
def api_analyze_page():
    """Analyze page content sent from the Firefox extension."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    url = data.get("url", "unknown")
    html = data.get("html", "")
    headers = data.get("headers", {})
    cookies = data.get("cookies", [])
    screenshot_b64 = data.get("screenshot")

    key_err = _check_api_key()
    if key_err:
        return jsonify({"error": key_err}), 503

    LOG.info(f"Analyzing page from extension: {url}")

    try:
        # If we have a screenshot, use vision analysis
        if screenshot_b64:
            result = analyze_page_with_vision(
                screenshot_b64=screenshot_b64,
                page_content=html,
                url=url,
            )
            return jsonify({
                "url": url,
                "ai_analysis": result.get("raw_text", ""),
                "analysis_type": "vision",
            })

        # Otherwise, parse and analyze the HTML
        # Build a pseudo page_data dict from the extension data
        page_data = {
            "url": url,
            "html": html,
            "headers": headers,
            "cookies": cookies,
            "scripts": [],
            "forms": [],
            "comments": [],
            "technologies": [],
            "security_headers": {},
        }

        # Run quick checks
        quick_findings = quick_vuln_check(page_data)

        # Send to AI
        ai_result = analyze_url_content(
            url=url,
            headers=headers,
            html=html,
            scripts=[],
            forms=[],
            cookies=cookies,
        )

        return jsonify({
            "url": url,
            "quick_findings": quick_findings,
            "ai_analysis": ai_result.get("raw_text", ""),
            "analysis_type": "content",
        })

    except Exception as e:
        LOG.error(f"Page analysis error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/screenshot", methods=["POST"])
def api_screenshot():
    """Analyze an uploaded screenshot with GPT-4 Vision."""
    data = request.get_json()
    if not data or "screenshot" not in data:
        return jsonify({"error": "Missing 'screenshot' field (base64 encoded)"}), 400

    key_err = _check_api_key()
    if key_err:
        return jsonify({"error": key_err}), 503

    try:
        result = analyze_page_with_vision(
            screenshot_b64=data["screenshot"],
            url=data.get("url", ""),
        )
        return jsonify({
            "ai_analysis": result.get("raw_text", ""),
            "tokens": result.get("tokens_estimated", 0),
        })

    except Exception as e:
        LOG.error(f"Screenshot analysis error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/knowledge-base", methods=["GET"])
def api_knowledge_base():
    """Return the attack surface knowledge base for reference."""
    category = request.args.get("category")
    if category and category in attack_surface_db.get("categories", {}):
        return jsonify(attack_surface_db["categories"][category])
    return jsonify({
        "categories": list(attack_surface_db.get("categories", {}).keys()),
        "default_credential_categories": list(attack_surface_db.get("default_credentials", {}).keys()),
    })


@app.route("/api/default-creds", methods=["GET"])
def api_default_creds():
    """Search default credentials database."""
    query = request.args.get("q", "").lower()
    results = {}
    for category, services in attack_surface_db.get("default_credentials", {}).items():
        for service, creds in services.items():
            if query in service.lower():
                results[service] = creds
    return jsonify(results)


@app.route("/api/status", methods=["GET"])
def api_status():
    """Health check endpoint."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    key_valid = bool(api_key) and not api_key.startswith("sk-proj-your")
    return jsonify({
        "status": "online",
        "api_configured": key_valid,
        "version": "1.0.0",
    })


def _match_attack_surface(technologies):
    """Cross-reference detected technologies with attack surface DB."""
    matches = []
    categories = attack_surface_db.get("categories", {})

    tech_names = {t.get("name", "").lower() for t in technologies}

    for cat_name, cat_data in categories.items():
        for tool_name, tool_data in cat_data.get("tools", {}).items():
            if tool_name.lower() in tech_names or any(
                tool_name.lower() in t for t in tech_names
            ):
                matches.append({
                    "technology": tool_name,
                    "category": cat_name,
                    "attack_vectors": tool_data.get("attack_vectors", []),
                    "default_creds": tool_data.get("default_creds", []),
                    "critical_cves": tool_data.get("critical_cves", []),
                })

    return matches


if __name__ == "__main__":
    port = int(os.environ.get("HACKAGENT_WEB_PORT", 5000))
    LOG.info(f"Starting HackAgent Web UI on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)
