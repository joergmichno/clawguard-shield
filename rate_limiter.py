"""
ClawGuard Shield — Rate Limiter
Sliding-window rate limiting using SQLite.
Free tier: monthly limit. Pro tier: daily limit. Enterprise: unlimited.
"""

from flask import request, jsonify

from auth import get_tier_limits
from database import get_request_count_today, get_request_count_month, increment_request_count


def check_rate_limit() -> tuple[bool, dict]:
    """
    Check if the current request is within rate limits.
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
        current_count = get_request_count_month(key_hash)
        if current_count >= monthly_limit:
            return False, {
                "limit": monthly_limit,
                "remaining": 0,
                "used": current_count,
                "tier": tier,
                "period": "month",
            }
        return True, {
            "limit": monthly_limit,
            "remaining": monthly_limit - current_count,
            "used": current_count,
            "tier": tier,
            "period": "month",
        }

    # Pro tier: daily limit
    current_count = get_request_count_today(key_hash)
    if current_count >= daily_limit:
        return False, {
            "limit": daily_limit,
            "remaining": 0,
            "used": current_count,
            "tier": tier,
            "period": "day",
        }

    return True, {
        "limit": daily_limit,
        "remaining": daily_limit - current_count,
        "used": current_count,
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


def record_request():
    """Record a successful request for rate limiting."""
    increment_request_count(request.key_hash)
