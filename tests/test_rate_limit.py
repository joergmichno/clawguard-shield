"""
Tests for rate limiting.
"""

from database import increment_request_count, get_request_count_today
from auth import hash_key


class TestRateLimiting:
    """Rate limit counting."""

    def test_initial_count_is_zero(self):
        count = get_request_count_today("nonexistent_hash")
        assert count == 0

    def test_increment_count(self):
        key_hash = hash_key("cgs_testkey_rate")
        increment_request_count(key_hash)
        assert get_request_count_today(key_hash) == 1

    def test_multiple_increments(self):
        key_hash = hash_key("cgs_testkey_multi")
        for _ in range(5):
            increment_request_count(key_hash)
        assert get_request_count_today(key_hash) == 5


class TestRateLimitEnforcement:
    """Rate limits enforced via API."""

    def test_free_tier_limit(self, client, api_key):
        """After 100 requests, should get 429."""
        from database import get_connection
        from auth import hash_key as hk

        # Simulate 100 requests by directly setting the counter
        key_hash = hk(api_key)
        conn = get_connection()
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conn.execute(
            "INSERT INTO rate_limits (key_hash, window_start, request_count) VALUES (?, ?, ?)",
            (key_hash, today, 100),
        )
        conn.commit()

        # 101st request should fail
        resp = client.post(
            "/api/v1/scan",
            json={"text": "test"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 429
        data = resp.get_json()
        assert data["error"] == "rate_limit_exceeded"
        assert "upgrade" in data["message"].lower() or "Upgrade" in data["message"]

    def test_under_limit_passes(self, client, api_key):
        """Under the limit should work fine."""
        resp = client.post(
            "/api/v1/scan",
            json={"text": "safe text"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
