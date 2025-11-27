import os, time, json, logging
from datetime import datetime
try:
    from anthropic import Anthropic, Response
except Exception:
    Anthropic = None

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("anthropic_client")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY")
_client = None

def _get_client():
    global _client
    if _client is None:
        if not ANTHROPIC_KEY:
            raise RuntimeError("No ANTHROPIC_API_KEY in environment")
        if Anthropic is None:
            raise RuntimeError("anthropic SDK not installed")
        _client = Anthropic(api_key=ANTHROPIC_KEY)
    return _client

# Simple budget guard (very conservative)
class Budget:
    def __init__(self, tokens_per_day=200_000, requests_per_minute=12):
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
    return text.replace(ANTHROPIC_KEY or "", "[REDACTED_API_KEY]")

def call_claude_messages(messages, model="claude-3.7-sonnet", max_tokens_to_sample=4000, temperature=0.0, budget=_DEFAULT_BUDGET, max_retries=3):
    client = _get_client()
    joined = " ".join([m["content"] if isinstance(m, dict) else str(m) for m in messages])
    est_tokens = max(1, len(joined) // 4)
    ok, reason = budget.allow(est_tokens=est_tokens)
    if not ok:
        raise RuntimeError(f"Budget denies request: {reason}")
    safe_messages = []
    for m in messages:
        content = m["content"] if isinstance(m, dict) else str(m)
        safe_messages.append({"role": m.get("role","user"), "content": scrub_for_api(content)})
    attempt = 0
    backoff = 1.0
    last_err = None
    while attempt <= max_retries:
        attempt += 1
        try:
            now = time.time()
            resp = client.messages.create(
                model=model,
                messages=safe_messages,
                max_tokens_to_sample=max_tokens_to_sample,
                temperature=temperature,
            )
            raw = getattr(resp, "completion", None) or getattr(resp, "content", None) or str(resp)
            tokens_used = est_tokens
            budget.consume(tokens=tokens_used, now_ts=now)
            meta = {"model": model, "timestamp": datetime.utcnow().isoformat()+"Z", "attempt": attempt}
            LOG.info(f"Claude response: model={model} attempt={attempt} len={len(raw)}")
            return {"raw": raw, "raw_text": raw, "tokens_estimated": tokens_used, "meta": meta}
        except Exception as e:
            last_err = e
            LOG.warning(f"Claude call error (attempt {attempt}): {e}")
            time.sleep(backoff)
            backoff *= 2.0
    raise RuntimeError(f"Claude API failed after {max_retries} attempts: last_err={last_err}")
