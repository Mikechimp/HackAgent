"""Tests for the Budget guard in models/anthropic_client.py."""
import time

from models.anthropic_client import Budget


class TestBudget:
    def test_allows_under_limit(self):
        b = Budget(tokens_per_day=1000, requests_per_minute=10)
        ok, reason = b.allow(est_tokens=100)
        assert ok is True
        assert reason is None

    def test_denies_over_token_limit(self):
        b = Budget(tokens_per_day=100, requests_per_minute=10)
        b.tokens_used = 90
        ok, reason = b.allow(est_tokens=50)
        assert ok is False
        assert reason == "token_budget_exceeded"

    def test_denies_over_rate_limit(self):
        b = Budget(tokens_per_day=100_000, requests_per_minute=2)
        now = time.time()
        b.req_timestamps = [now, now]
        ok, reason = b.allow(est_tokens=1)
        assert ok is False
        assert reason == "rate_limit_qps"

    def test_consume_increments(self):
        b = Budget()
        b.consume(tokens=500)
        assert b.tokens_used == 500
        b.consume(tokens=300)
        assert b.tokens_used == 800

    def test_daily_reset(self):
        b = Budget(tokens_per_day=1000)
        b.tokens_used = 999
        from datetime import date, timedelta
        b.reset_day = date.today() - timedelta(days=1)
        ok, _ = b.allow(est_tokens=100)
        assert ok is True
        assert b.tokens_used == 0
