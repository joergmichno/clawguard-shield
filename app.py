"""
ClawGuard Shield API v1.0
REST API for AI agent security scanning.

Endpoints:
    POST /api/v1/scan      — Scan text for threats
    GET  /api/v1/health     — Service health check
    GET  /api/v1/patterns   — List detection patterns
    GET  /api/v1/usage      — Usage statistics
    POST /api/v1/register   — Register for a free API key
    POST /api/v1/upgrade    — Upgrade to Pro/Enterprise (Stripe)
    POST /api/v1/billing    — Manage subscription (Stripe Portal)
    POST /api/v1/webhook/stripe — Stripe webhook receiver

(c) 2026 Jörg Michno
"""

import time
import os
from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta

from clawguard import scan_text, ALL_PATTERNS, Severity
from auth import (
    require_api_key,
    generate_api_key,
    hash_key,
    get_key_prefix,
    get_tier_limits,
    TIER_LIMITS,
)
from rate_limiter import check_rate_limit, rate_limit_response, record_request
from database import (
    init_db,
    insert_api_key,
    log_usage,
    get_usage_stats,
    email_exists,
    get_request_count_today,
    cleanup_old_rate_limits,
    get_all_emails,
)
from models import ScanRequest, ScanResponse, RegisterRequest, HealthResponse
from payments import (
    create_checkout_session,
    create_billing_portal_session,
    verify_webhook,
    handle_checkout_completed,
    handle_subscription_updated,
    handle_subscription_deleted,
    get_stripe_customer_id,
)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ─── Startup ──────────────────────────────────────────────────────────────────

with app.app_context():
    init_db()


# ─── CORS Headers ─────────────────────────────────────────────────────────────

@app.after_request
def add_cors_headers(response):
    """Add CORS headers for browser-based API clients."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.before_request
def handle_preflight():
    """Handle CORS preflight requests."""
    if request.method == "OPTIONS":
        return "", 204


# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not_found", "message": "Endpoint not found."}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "method_not_allowed", "message": "HTTP method not allowed."}), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "internal_error", "message": "Internal server error."}), 500


# ─── GET /api/v1/ ─────────────────────────────────────────────────────────────

@app.route("/api/v1/", methods=["GET"])
@app.route("/api/v1", methods=["GET"])
def api_index():
    """API overview — shown when someone visits the base URL."""
    return jsonify({
        "service": "ClawGuard Shield",
        "version": "1.0.0",
        "description": "AI Agent Security Scanning API",
        "endpoints": {
            "POST /api/v1/scan": "Scan text for security threats (requires API key)",
            "GET  /api/v1/health": "Service health check",
            "GET  /api/v1/patterns": "List all detection patterns (requires API key)",
            "GET  /api/v1/usage": "Your usage statistics (requires API key)",
            "POST /api/v1/register": "Get a free API key",
            "POST /api/v1/upgrade": "Upgrade to Pro or Enterprise (requires API key)",
            "POST /api/v1/billing": "Manage subscription via Stripe (requires API key)",
        },
        "docs": "https://prompttools.co/shield",
        "github": "https://github.com/joergmichno/clawguard-shield",
    }), 200


# ─── POST /api/v1/scan ───────────────────────────────────────────────────────

@app.route("/api/v1/scan", methods=["POST"])
@require_api_key
def api_scan():
    """Scan text for security threats."""
    start_time = time.time()

    # Parse request
    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "error": "invalid_json",
            "message": "Request body must be valid JSON with a 'text' field.",
        }), 400

    # Build scan request
    tier = request.key_data.get("tier", "free")
    limits = get_tier_limits(tier)

    scan_req = ScanRequest(
        text=data.get("text", ""),
        source=data.get("source", "api"),
    )

    # Validate
    error = scan_req.validate(max_length=limits["max_text_length"])
    if error:
        return jsonify({"error": "validation_error", "message": error}), 400

    # Check rate limit
    allowed, rate_info = check_rate_limit()
    if not allowed:
        return rate_limit_response(rate_info)

    # Run ClawGuard scan
    report = scan_text(scan_req.text, source=scan_req.source)

    elapsed_ms = int((time.time() - start_time) * 1000)

    # Build response
    response = ScanResponse(
        clean=report.total_findings == 0,
        risk_score=report.risk_score,
        severity=report.risk_level,
        findings_count=report.total_findings,
        findings=[
            {
                "pattern_name": f.pattern_name,
                "severity": f.severity.value,
                "category": f.category,
                "matched_text": f.matched_text,
                "line_number": f.line_number,
                "description": f.recommendation,
            }
            for f in report.findings
        ],
        scan_time_ms=elapsed_ms,
    )

    # Record usage
    record_request()
    log_usage(
        key_hash=request.key_hash,
        endpoint="/api/v1/scan",
        text_length=len(scan_req.text),
        findings_count=report.total_findings,
        risk_score=report.risk_score,
        response_time_ms=elapsed_ms,
    )

    # Add rate limit headers
    resp = jsonify(response.to_dict())
    if rate_info.get("limit") != "unlimited":
        resp.headers["X-RateLimit-Limit"] = str(rate_info.get("limit", 100))
        resp.headers["X-RateLimit-Remaining"] = str(max(0, rate_info.get("remaining", 0) - 1))

    return resp, 200


# ─── GET /api/v1/health ──────────────────────────────────────────────────────

@app.route("/api/v1/health", methods=["GET"])
def api_health():
    """Service health check (no auth required)."""
    health = HealthResponse(
        patterns_count=len(ALL_PATTERNS),
    )
    return jsonify(health.to_dict()), 200


# ─── GET /api/v1/patterns ────────────────────────────────────────────────────

@app.route("/api/v1/patterns", methods=["GET"])
@require_api_key
def api_patterns():
    """List all detection patterns."""
    categories = {}
    for name, pattern, severity, category, recommendation in ALL_PATTERNS:
        if category not in categories:
            categories[category] = []
        categories[category].append({
            "name": name,
            "severity": severity.value,
            "description": recommendation,
        })

    return jsonify({
        "total_patterns": len(ALL_PATTERNS),
        "categories": categories,
        "api_version": "1.0",
    }), 200


# ─── GET /api/v1/usage ───────────────────────────────────────────────────────

@app.route("/api/v1/usage", methods=["GET"])
@require_api_key
def api_usage():
    """Get usage statistics for the authenticated API key."""
    key_hash = request.key_hash
    key_data = request.key_data
    tier = key_data.get("tier", "free")
    limits = get_tier_limits(tier)

    # Get today's count
    today_count = get_request_count_today(key_hash)

    # Get overall stats (last 30 days)
    since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    stats = get_usage_stats(key_hash, since=since)

    daily_limit = limits["daily_limit"]

    return jsonify({
        "tier": tier,
        "tier_name": limits["name"],
        "daily_limit": daily_limit if daily_limit else "unlimited",
        "today_used": today_count,
        "today_remaining": (daily_limit - today_count) if daily_limit else "unlimited",
        "last_30_days": stats,
        "key_prefix": key_data.get("key_prefix", "???"),
        "created_at": key_data.get("created_at", ""),
        "api_version": "1.0",
    }), 200


# ─── POST /api/v1/register ───────────────────────────────────────────────────

@app.route("/api/v1/register", methods=["POST"])
def api_register():
    """Register for a free API key."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "error": "invalid_json",
            "message": "Request body must be valid JSON with an 'email' field.",
        }), 400

    reg = RegisterRequest(
        email=data.get("email", "").strip().lower(),
        newsletter=bool(data.get("newsletter", False)),
    )

    # Validate
    error = reg.validate()
    if error:
        return jsonify({"error": "validation_error", "message": error}), 400

    # Check duplicate
    if email_exists(reg.email):
        return jsonify({
            "error": "email_exists",
            "message": "An API key already exists for this email. Contact support if you lost your key.",
        }), 409

    # Generate key
    raw_key = generate_api_key()
    key_hash = hash_key(raw_key)
    key_prefix = get_key_prefix(raw_key)

    # Store
    insert_api_key(
        key_hash=key_hash, key_prefix=key_prefix, email=reg.email, tier="free",
        newsletter_consent=reg.newsletter,
    )

    return jsonify({
        "message": "API key created successfully. Store it safely — it cannot be recovered!",
        "api_key": raw_key,
        "tier": "free",
        "daily_limit": TIER_LIMITS["free"]["daily_limit"],
        "max_text_length": TIER_LIMITS["free"]["max_text_length"],
    }), 201


# ─── POST /api/v1/upgrade ────────────────────────────────────────────────────

@app.route("/api/v1/upgrade", methods=["POST"])
@require_api_key
def api_upgrade():
    """Upgrade to Pro or Enterprise via Stripe Checkout."""
    data = request.get_json(silent=True) or {}
    tier = data.get("tier", "pro").lower()

    if tier not in ("pro", "enterprise"):
        return jsonify({
            "error": "invalid_tier",
            "message": "Tier must be 'pro' or 'enterprise'.",
        }), 400

    current_tier = request.key_data.get("tier", "free")
    if current_tier == tier:
        return jsonify({
            "error": "already_on_tier",
            "message": f"You are already on the {tier} tier.",
        }), 400

    email = request.key_data.get("email", "")
    checkout_url = create_checkout_session(
        email=email,
        key_hash=request.key_hash,
        tier=tier,
    )

    if not checkout_url:
        return jsonify({
            "error": "checkout_error",
            "message": "Could not create checkout session. Payment may not be configured yet.",
        }), 503

    return jsonify({
        "message": f"Redirect to Stripe to upgrade to {tier}.",
        "checkout_url": checkout_url,
    }), 200


# ─── POST /api/v1/webhook/stripe ────────────────────────────────────────────

@app.route("/api/v1/webhook/stripe", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events (no auth — validated by signature)."""
    payload = request.get_data()
    signature = request.headers.get("Stripe-Signature", "")

    event = verify_webhook(payload, signature)
    if not event:
        return jsonify({"error": "invalid_signature"}), 400

    event_type = event.get("type", "")

    if event_type == "checkout.session.completed":
        handle_checkout_completed(event)
    elif event_type == "customer.subscription.updated":
        handle_subscription_updated(event)
    elif event_type == "customer.subscription.deleted":
        handle_subscription_deleted(event)

    # Always return 200 to acknowledge receipt
    return jsonify({"received": True}), 200


# ─── POST /api/v1/billing ───────────────────────────────────────────────────

@app.route("/api/v1/billing", methods=["POST"])
@require_api_key
def api_billing():
    """Redirect to Stripe Customer Portal for subscription management."""
    customer_id = get_stripe_customer_id(request.key_hash)

    if not customer_id:
        return jsonify({
            "error": "no_subscription",
            "message": "No active subscription found. Upgrade first at /api/v1/upgrade.",
        }), 404

    portal_url = create_billing_portal_session(customer_id)
    if not portal_url:
        return jsonify({
            "error": "portal_error",
            "message": "Could not create billing portal session.",
        }), 503

    return jsonify({
        "message": "Redirect to Stripe billing portal.",
        "portal_url": portal_url,
    }), 200


# ─── Admin Endpoints ─────────────────────────────────────────────────────────

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


@app.route("/api/v1/admin/emails", methods=["GET"])
def admin_emails():
    """Export registered emails (admin-only, token-protected)."""
    token = request.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized", "message": "Invalid admin token."}), 403

    newsletter_only = request.args.get("newsletter", "").lower() in ("true", "1", "yes")
    fmt = request.args.get("format", "json").lower()

    emails = get_all_emails(newsletter_only=newsletter_only)

    if fmt == "csv":
        lines = ["email,tier,created_at,newsletter_consent"]
        for e in emails:
            lines.append(f"{e['email']},{e['tier']},{e['created_at']},{e['newsletter_consent']}")
        return "\n".join(lines), 200, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=emails.csv"}

    return jsonify({"total": len(emails), "emails": emails}), 200


# ─── Maintenance ──────────────────────────────────────────────────────────────

@app.cli.command("cleanup")
def cleanup():
    """Clean up old rate limit data."""
    cleanup_old_rate_limits(days=7)
    print("Cleanup done.")


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=True)
