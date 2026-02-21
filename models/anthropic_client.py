import os, time, json, logging
from datetime import datetime
try:
    from anthropic import Anthropic
except Exception:
    Anthropic = None

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("anthropic_client")
_client = None


def _get_api_key():
    """Get API key, checking env var (which may have been loaded from .env)."""
    return os.environ.get("ANTHROPIC_API_KEY")


def _get_client():
    global _client
    if _client is None:
        api_key = _get_api_key()
        if not api_key:
            raise RuntimeError(
                "No ANTHROPIC_API_KEY configured. "
                "Set ANTHROPIC_API_KEY in your .env file with a real key from "
                "https://console.anthropic.com/settings/keys"
            )
        if Anthropic is None:
            raise RuntimeError(
                "anthropic SDK not installed. Run: pip install anthropic"
            )
        _client = Anthropic(api_key=api_key)
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

def scrub_for_api(text: str) -> str:
    if not text:
        return text
    api_key = _get_api_key()
    if api_key:
        return text.replace(api_key, "[REDACTED_API_KEY]")
    return text

def call_claude_messages(messages, model="claude-sonnet-4-20250514", max_tokens=4000, temperature=0.0, budget=None, max_retries=3):
    """Call the Claude Messages API with budget guards and retries.

    Args:
        messages: List of message dicts with 'role' and 'content' keys.
        model: Model identifier to use.
        max_tokens: Maximum tokens in the response.
        temperature: Sampling temperature (0.0 = deterministic).
        budget: Budget instance for rate/token limiting (uses default if None).
        max_retries: Number of retry attempts on transient failures.
    """
    if budget is None:
        budget = _DEFAULT_BUDGET
    client = _get_client()
    joined = " ".join([m["content"] if isinstance(m, dict) else str(m) for m in messages])
    est_tokens = max(1, len(joined) // 4)
    ok, reason = budget.allow(est_tokens=est_tokens)
    if not ok:
        raise RuntimeError(f"Budget denies request: {reason}")

    # Separate system message from conversation messages
    system_text = None
    api_messages = []
    for m in messages:
        content = m["content"] if isinstance(m, dict) else str(m)
        role = m.get("role", "user") if isinstance(m, dict) else "user"
        safe_content = scrub_for_api(content)
        if role == "system":
            system_text = safe_content
        else:
            api_messages.append({"role": role, "content": safe_content})

    attempt = 0
    backoff = 1.0
    last_err = None
    while attempt < max_retries:
        attempt += 1
        try:
            now = time.time()
            kwargs = dict(
                model=model,
                messages=api_messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            if system_text:
                kwargs["system"] = system_text
            resp = client.messages.create(**kwargs)
            # Extract text from the response content blocks
            if hasattr(resp, "content") and isinstance(resp.content, list):
                raw = "".join(
                    block.text for block in resp.content
                    if hasattr(block, "text")
                )
            else:
                raw = str(resp)
            tokens_used = getattr(resp, "usage", None)
            if tokens_used:
                actual = getattr(tokens_used, "input_tokens", 0) + getattr(tokens_used, "output_tokens", 0)
            else:
                actual = est_tokens
            budget.consume(tokens=actual, now_ts=now)
            meta = {"model": model, "timestamp": datetime.utcnow().isoformat()+"Z", "attempt": attempt}
            LOG.info(f"Claude response: model={model} attempt={attempt} tokens={actual}")
            return {"raw": raw, "raw_text": raw, "tokens_estimated": actual, "meta": meta}
        except Exception as e:
            last_err = e
            LOG.warning(f"Claude call error (attempt {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(backoff)
                backoff *= 2.0
    raise RuntimeError(f"Claude API failed after {max_retries} attempts: {last_err}")
