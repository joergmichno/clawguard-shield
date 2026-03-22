"""
ClawGuard Shield — Rate Limiter
Atomic rate limiting using SQLite BEGIN IMMEDIATE transactions.
Free tier: monthly limit. Pro tier: daily limit. Enterprise: unlimited.
"""

from flask import request, jsonify

from auth import get_tier_limits
from database import atomic_check_and_increment


def check_and_record_request() -> tuple[bool, dict]:
    """
    Atomically check rate limit AND record the request in one transaction.
    Replaces the old check_rate_limit() + record_request() two-step pattern
    which had a race condition under concurrent requests.

    Must be called after require_api_key (needs request.key_data).

    Returns:
        (allowed: bool, info: dict with limit/remaining/reset details)
    """
    key_data = request.key_data
    key_hash = request.key_hash
    tier = key_data.get("tier", "free")
    limits = get_tier_limits(tier)

    daily_limit = limits["daily_limit"]
    monthly_limit = limits.get("monthly_limit")

    # Enterprise = unlimited (both None)
    if daily_limit is None and monthly_limit is None:
        return True, {
            "limit": "unlimited",
            "remaining": "unlimited",
            "tier": tier,
        }

    # Free tier: monthly limit
    if monthly_limit is not None:
        allowed, current = atomic_check_and_increment(key_hash, monthly_limit, "month")
        return allowed, {
            "limit": monthly_limit,
            "remaining": max(0, monthly_limit - current),
            "used": current,
            "tier": tier,
            "period": "month",
        }

    # Pro tier: daily limit
    allowed, current = atomic_check_and_increment(key_hash, daily_limit, "day")
    return allowed, {
        "limit": daily_limit,
        "remaining": max(0, daily_limit - current),
        "used": current,
        "tier": tier,
        "period": "day",
    }


def rate_limit_response(info: dict):
    """Return a 429 rate limit exceeded response."""
    period = info.get("period", "day")
    if period == "month":
        message = f"Monthly limit of {info['limit']} scans exceeded. Upgrade to Pro for 1,000 scans/day."
    else:
        message = f"Daily limit of {info['limit']} requests exceeded. Upgrade to Enterprise for unlimited."

    return jsonify({
        "error": "rate_limit_exceeded",
        "message": message,
        "tier": info["tier"],
        "limit": info["limit"],
        "used": info.get("used", 0),
        "period": period,
        "upgrade_url": "https://prompttools.co/shield#pricing",
    }), 429
