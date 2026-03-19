"""
ClawGuard Shield — Authentication
API key generation, hashing, and validation.
"""

import hashlib
import secrets
from functools import wraps
from flask import request, jsonify

from database import get_api_key, update_last_used

# API key format: cgs_ + 32 hex chars = 36 chars total
KEY_PREFIX = "cgs_"
KEY_LENGTH = 32  # hex chars after prefix


def generate_api_key() -> str:
    """Generate a new API key with cgs_ prefix."""
    raw = secrets.token_hex(KEY_LENGTH // 2)  # 16 bytes = 32 hex chars
    return f"{KEY_PREFIX}{raw}"


def hash_key(api_key: str) -> str:
    """SHA-256 hash an API key for storage."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def get_key_prefix(api_key: str) -> str:
    """Extract a safe prefix for display (first 12 chars)."""
    return api_key[:12] + "..."


def validate_key_format(api_key: str) -> bool:
    """Check if a key has valid format (cgs_ + hex)."""
    if not api_key.startswith(KEY_PREFIX):
        return False
    hex_part = api_key[len(KEY_PREFIX):]
    if len(hex_part) != KEY_LENGTH:
        return False
    try:
        int(hex_part, 16)
        return True
    except ValueError:
        return False


def require_api_key(f):
    """Decorator: require a valid API key in X-API-Key header."""

    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key", "").strip()

        if not api_key:
            return jsonify({
                "error": "missing_api_key",
                "message": "Provide your API key in the X-API-Key header.",
            }), 401

        if not validate_key_format(api_key):
            return jsonify({
                "error": "invalid_key_format",
                "message": "Invalid API key format. Keys start with 'cgs_'.",
            }), 401

        key_hash = hash_key(api_key)
        key_data = get_api_key(key_hash)

        if not key_data:
            return jsonify({
                "error": "invalid_api_key",
                "message": "API key not found or deactivated.",
            }), 403

        # Attach key data to request for downstream use
        request.key_data = key_data
        request.key_hash = key_hash

        # Update last used
        update_last_used(key_hash)

        return f(*args, **kwargs)

    return decorated


# ─── Tier Configuration ───────────────────────────────────────────────────────

TIER_LIMITS = {
    "free": {
        "daily_limit": None,  # not daily-limited
        "monthly_limit": 3,
        "max_text_length": 5_000,
        "name": "Free",
        "price_eur": 0,
    },
    "pro": {
        "daily_limit": 1_000,
        "monthly_limit": None,
        "max_text_length": 50_000,
        "name": "Pro",
        "price_eur": 49,
    },
    "enterprise": {
        "daily_limit": None,  # unlimited
        "monthly_limit": None,
        "max_text_length": 200_000,
        "name": "Enterprise",
        "price_eur": 199,
    },
}


def get_tier_limits(tier: str) -> dict:
    """Get rate limits for a tier. Defaults to free."""
    return TIER_LIMITS.get(tier, TIER_LIMITS["free"])
