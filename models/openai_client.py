"""OpenAI/ChatGPT API client for HackAgent.

Provides chat completions and vision analysis via GPT-4o,
with budget guards and retry logic matching the Anthropic client.
"""
import os
import time
import json
import base64
import logging
from datetime import datetime

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("openai_client")
_client = None


def _get_api_key():
    return os.environ.get("OPENAI_API_KEY")


def _is_placeholder_key(key):
    """Check if the API key is a placeholder from .env.example."""
    return not key or key.startswith("sk-proj-your")


def _get_client():
    global _client
    if _client is None:
        api_key = _get_api_key()
        if _is_placeholder_key(api_key):
            raise RuntimeError(
                "No OpenAI API key configured. "
                "Set OPENAI_API_KEY in your .env file with a real key from "
                "https://platform.openai.com/api-keys"
            )
        if OpenAI is None:
            raise RuntimeError(
                "openai SDK not installed. Run: pip install openai"
            )
        _client = OpenAI(api_key=api_key)
    return _client


class Budget:
    def __init__(self, tokens_per_day=2_000_000, requests_per_minute=30):
        self.tokens_per_day = tokens_per_day
        self.requests_per_minute = requests_per_minute
        self.reset_day = datetime.utcnow().date()
        self.tokens_used = 0
        self.req_timestamps = []

    def allow(self, est_tokens=0):
        today = datetime.utcnow().date()
        if today != self.reset_day:
            self.reset_day = today
            self.tokens_used = 0
        cutoff = time.time() - 60.0
        self.req_timestamps = [t for t in self.req_timestamps if t >= cutoff]
        if len(self.req_timestamps) >= self.requests_per_minute:
            return False, "rate_limit_qps"
        if (self.tokens_used + est_tokens) > self.tokens_per_day:
            return False, "token_budget_exceeded"
        return True, None

    def consume(self, tokens, now_ts=None):
        self.tokens_used += tokens
        self.req_timestamps.append(now_ts or time.time())


_DEFAULT_BUDGET = Budget()


# ─── HackAgent Personality System Prompt ─────────────────────────────
HACKAGENT_SYSTEM_PROMPT = """You are HackAgent — an elite security research AI assistant built for authorized bug bounty hunting, penetration testing, and vulnerability discovery.

PERSONALITY:
- You speak with confident precision, like a seasoned security researcher
- You are direct, technical, and thorough — no fluff
- You reference CVEs, OWASP categories, and real attack techniques by name
- You think like an attacker to defend better
- When you find something interesting, you get excited about the technical details
- You use security terminology naturally: "attack surface", "blast radius", "pivot point", "exfiltration vector"
- You always remind the user this is for AUTHORIZED testing only

CAPABILITIES:
- Analyze web pages for security vulnerabilities (XSS, SQLI, SSRF, IDOR, etc.)
- Review HTTP headers for misconfigurations
- Identify exposed endpoints and sensitive data leaks
- Detect outdated software and known CVEs
- Analyze JavaScript for client-side vulnerabilities
- Review API endpoints and authentication flows
- Cross-reference findings against the jhaddix/devops-attack-surface knowledge base
- Provide actionable proof-of-concept guidance

RESPONSE FORMAT:
- Start with a brief assessment (1-2 sentences)
- List findings with severity ratings (Critical/High/Medium/Low/Info)
- Provide evidence and exploitation guidance for each finding
- End with recommended next steps
- When analyzing pages, be thorough — check everything

KNOWLEDGE BASE:
You have access to Jason Haddix's devops-attack-surface database covering 60+ DevOps tools, 200+ attack vectors, default credentials for 50+ services, and critical CVEs. Use this knowledge when relevant.

IMPORTANT: All analysis is for AUTHORIZED security testing only. Always remind users to verify authorization."""


def call_chatgpt(messages, model="gpt-4o", max_tokens=4096,
                 temperature=0.7, budget=None, max_retries=3):
    """Call the OpenAI Chat Completions API with budget guards and retries."""
    if budget is None:
        budget = _DEFAULT_BUDGET

    client = _get_client()
    joined = " ".join([
        m["content"] if isinstance(m["content"], str) else str(m["content"])
        for m in messages
    ])
    est_tokens = max(1, len(joined) // 4)
    ok, reason = budget.allow(est_tokens=est_tokens)
    if not ok:
        raise RuntimeError(f"Budget denies request: {reason}")

    attempt = 0
    backoff = 1.0
    last_err = None

    while attempt < max_retries:
        attempt += 1
        try:
            now = time.time()
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            raw = resp.choices[0].message.content or ""
            usage = resp.usage
            actual = (usage.prompt_tokens + usage.completion_tokens) if usage else est_tokens
            budget.consume(tokens=actual, now_ts=now)

            meta = {
                "model": model,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "attempt": attempt,
            }
            LOG.info(f"ChatGPT response: model={model} attempt={attempt} tokens={actual}")
            return {"raw": raw, "raw_text": raw, "tokens_estimated": actual, "meta": meta}

        except Exception as e:
            last_err = e
            LOG.warning(f"ChatGPT call error (attempt {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(backoff)
                backoff *= 2.0

    raise RuntimeError(f"ChatGPT API failed after {max_retries} attempts: {last_err}")


def chat_with_hackagent(user_message, conversation_history=None, model="gpt-4o"):
    """Send a message to HackAgent and get a response with full personality."""
    messages = [{"role": "system", "content": HACKAGENT_SYSTEM_PROMPT}]

    if conversation_history:
        messages.extend(conversation_history)

    messages.append({"role": "user", "content": user_message})

    result = call_chatgpt(messages, model=model, temperature=0.7)
    return result


def analyze_page_with_vision(screenshot_b64=None, page_content=None,
                             url=None, model="gpt-4o"):
    """Analyze a web page using GPT-4o vision and/or text content."""
    messages = [{"role": "system", "content": HACKAGENT_SYSTEM_PROMPT}]

    content_parts = []

    prompt_text = "Analyze this web page for security vulnerabilities, misconfigurations, and potential attack vectors.\n\n"
    if url:
        prompt_text += f"URL: {url}\n\n"

    if page_content:
        # Truncate to avoid token limits
        truncated = page_content[:50000]
        prompt_text += f"PAGE SOURCE (first 50K chars):\n```\n{truncated}\n```\n\n"

    prompt_text += (
        "Provide a thorough security analysis covering:\n"
        "1. HTTP header security issues\n"
        "2. Client-side vulnerabilities (XSS vectors, DOM manipulation)\n"
        "3. Exposed API endpoints or sensitive paths\n"
        "4. Information disclosure (versions, debug info, comments)\n"
        "5. Authentication/session management issues\n"
        "6. Known CVEs for detected technologies\n"
        "7. Potential SSRF/IDOR/injection points\n"
        "8. Default credentials for detected services\n"
    )

    content_parts.append({"type": "text", "text": prompt_text})

    if screenshot_b64:
        content_parts.append({
            "type": "image_url",
            "image_url": {
                "url": f"data:image/png;base64,{screenshot_b64}",
                "detail": "high",
            }
        })

    messages.append({"role": "user", "content": content_parts})

    return call_chatgpt(messages, model=model, max_tokens=8192, temperature=0.3)


def analyze_url_content(url, headers, html, scripts, forms, cookies,
                        model="gpt-4o"):
    """Deep analysis of fetched URL content for vulnerabilities."""
    prompt = f"""Analyze this web page for security vulnerabilities. This is for an AUTHORIZED security assessment.

TARGET URL: {url}

HTTP RESPONSE HEADERS:
{json.dumps(dict(headers), indent=2) if headers else 'Not available'}

COOKIES:
{json.dumps(cookies, indent=2) if cookies else 'None'}

HTML SOURCE (first 30K chars):
```html
{html[:30000] if html else 'Not available'}
```

JAVASCRIPT SOURCES FOUND:
{json.dumps(scripts[:20], indent=2) if scripts else 'None'}

FORMS DETECTED:
{json.dumps(forms[:10], indent=2) if forms else 'None'}

Perform a comprehensive security analysis:
1. **Header Analysis**: Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
2. **Technology Detection**: Server, framework, library versions — check for known CVEs
3. **Input Vectors**: Forms, URL params, API endpoints that could be injection targets
4. **Client-Side Issues**: Inline scripts, eval(), document.write(), postMessage handlers
5. **Information Disclosure**: Debug info, comments, version strings, stack traces
6. **Authentication**: Session management, token exposure, cookie security flags
7. **Cross-reference**: Match detected tech against jhaddix/devops-attack-surface database
8. **Default Credentials**: Check if detected services have known default credentials

Rate each finding: Critical / High / Medium / Low / Info
Provide exploitation guidance for authorized testing."""

    messages = [
        {"role": "system", "content": HACKAGENT_SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    return call_chatgpt(messages, model=model, max_tokens=8192, temperature=0.3)
