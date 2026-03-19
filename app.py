"""
ClawGuard Shield API v1.0
REST API for AI agent security scanning.

Endpoints:
    POST /api/v1/scan      — Scan text for threats
    POST /api/v1/scan-url  — Fetch and scan a URL
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
from flask import Flask, request, jsonify, Response
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
from report_generator import generate_compliance_report

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


# ─── GET /api/docs (redirect) ────────────────────────────────────────────────

@app.route("/api/docs", methods=["GET"])
@app.route("/api/v1/docs", methods=["GET"])
@app.route("/api/v1/redoc", methods=["GET"])
def api_docs_redirect():
    """Redirect docs URLs to the API index with full endpoint listing."""
    from flask import redirect
    return redirect("/api/v1/", code=302)


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
            "POST /api/v1/scan-url": "Fetch and scan a URL for threats (requires API key)",
            "GET  /api/v1/health": "Service health check",
            "GET  /api/v1/patterns": "List all detection patterns (requires API key)",
            "GET  /api/v1/usage": "Your usage statistics (requires API key)",
            "POST /api/v1/report": "Generate PDF compliance report (requires API key)",
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
                "confidence": f.confidence,
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


# ─── POST /api/v1/report ─────────────────────────────────────────────────────

@app.route("/api/v1/report", methods=["POST"])
@require_api_key
def api_report():
    """Generate a PDF compliance report from a scan.

    Accepts the same input as /scan but returns a PDF document instead of JSON.
    Optional fields: company_name (for the cover page).
    """
    start_time = time.time()

    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "error": "invalid_json",
            "message": "Request body must be valid JSON with a 'text' field.",
        }), 400

    tier = request.key_data.get("tier", "free")
    limits = get_tier_limits(tier)

    scan_req = ScanRequest(
        text=data.get("text", ""),
        source=data.get("source", "report"),
    )

    error = scan_req.validate(max_length=limits["max_text_length"])
    if error:
        return jsonify({"error": "validation_error", "message": error}), 400

    allowed, rate_info = check_rate_limit()
    if not allowed:
        return rate_limit_response(rate_info)

    # Run scan
    report = scan_text(scan_req.text, source=scan_req.source)
    elapsed_ms = int((time.time() - start_time) * 1000)

    # Build scan data dict for the report generator
    scan_data = {
        "clean": report.total_findings == 0,
        "risk_score": report.risk_score,
        "severity": report.risk_level,
        "findings_count": report.total_findings,
        "findings": [
            {
                "pattern_name": f.pattern_name,
                "severity": f.severity.value,
                "category": f.category,
                "matched_text": f.matched_text,
                "line_number": f.line_number,
                "description": f.recommendation,
                "confidence": f.confidence,
            }
            for f in report.findings
        ],
        "scan_time_ms": elapsed_ms,
    }

    company_name = data.get("company_name", "")

    # Generate PDF
    try:
        pdf_bytes = bytes(generate_compliance_report(scan_data, company_name=company_name))
    except Exception as e:
        return jsonify({
            "error": "report_generation_error",
            "message": f"Failed to generate report: {str(e)}",
        }), 500

    # Record usage
    record_request()
    log_usage(
        key_hash=request.key_hash,
        endpoint="/api/v1/report",
        text_length=len(scan_req.text),
        findings_count=report.total_findings,
        risk_score=report.risk_score,
        response_time_ms=elapsed_ms,
    )

    # Return PDF
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"clawguard-report-{timestamp}.pdf"

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


# ─── POST /api/v1/scan-url ───────────────────────────────────────────────────

@app.route("/api/v1/scan-url", methods=["POST"])
@require_api_key
def api_scan_url():
    """Fetch a URL and scan its content for security threats."""
    import urllib.request
    import urllib.error
    import html as html_module
    import re

    start_time = time.time()

    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "error": "invalid_json",
            "message": "Request body must be valid JSON with a 'url' field.",
        }), 400

    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "validation_error", "message": "Field 'url' is required."}), 400

    # Basic URL validation
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "validation_error", "message": "URL must start with http:// or https://."}), 400

    # SSRF Protection: Block private/internal IP ranges
    import socket
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return jsonify({"error": "validation_error", "message": "Invalid URL hostname."}), 400
        resolved_ip = socket.getaddrinfo(hostname, None)[0][4][0]
        import ipaddress
        ip = ipaddress.ip_address(resolved_ip)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return jsonify({"error": "ssrf_blocked", "message": "Access to internal/private IP addresses is not allowed."}), 403
    except (socket.gaierror, ValueError) as e:
        return jsonify({"error": "validation_error", "message": f"Cannot resolve hostname: {str(e)}"}), 400

    tier = request.key_data.get("tier", "free")
    limits = get_tier_limits(tier)

    # Check rate limit
    allowed, rate_info = check_rate_limit()
    if not allowed:
        return rate_limit_response(rate_info)

    # Fetch URL content (SSRF-safe: IP already validated)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ClawGuard-Shield/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read(limits["max_text_length"] + 1000)
            text = raw.decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return jsonify({"error": "fetch_error", "message": f"Could not fetch URL: {str(e.reason)}"}), 422
    except Exception as e:
        return jsonify({"error": "fetch_error", "message": f"Could not fetch URL: {str(e)}"}), 422

    # Strip HTML tags to get text content
    if "html" in content_type.lower():
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = html_module.unescape(text)
        text = re.sub(r'\s+', ' ', text).strip()

    # Enforce text length limit
    if len(text) > limits["max_text_length"]:
        text = text[:limits["max_text_length"]]

    # Run scan
    report = scan_text(text, source="url")
    elapsed_ms = int((time.time() - start_time) * 1000)

    response_data = {
        "url": url,
        "content_length": len(text),
        "clean": report.total_findings == 0,
        "risk_score": report.risk_score,
        "severity": report.risk_level,
        "findings_count": report.total_findings,
        "findings": [
            {
                "pattern_name": f.pattern_name,
                "severity": f.severity.value,
                "category": f.category,
                "matched_text": f.matched_text,
                "description": f.recommendation,
                "confidence": f.confidence,
            }
            for f in report.findings
        ],
        "scan_time_ms": elapsed_ms,
    }

    # Record usage
    record_request()
    log_usage(
        key_hash=request.key_hash,
        endpoint="/api/v1/scan-url",
        text_length=len(text),
        findings_count=report.total_findings,
        risk_score=report.risk_score,
        response_time_ms=elapsed_ms,
    )

    return jsonify(response_data), 200


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
    monthly_limit = limits.get("monthly_limit")

    # Build limit info based on tier type
    if monthly_limit is not None:
        from database import get_request_count_month
        month_count = get_request_count_month(key_hash)
        limit_info = {
            "period": "month",
            "limit": monthly_limit,
            "used": month_count,
            "remaining": max(0, monthly_limit - month_count),
        }
    elif daily_limit is not None:
        limit_info = {
            "period": "day",
            "limit": daily_limit,
            "used": today_count,
            "remaining": max(0, daily_limit - today_count),
        }
    else:
        limit_info = {
            "period": "unlimited",
            "limit": "unlimited",
            "used": today_count,
            "remaining": "unlimited",
        }

    return jsonify({
        "tier": tier,
        "tier_name": limits["name"],
        "rate_limit": limit_info,
        "last_30_days": stats,
        "key_prefix": key_data.get("key_prefix", "???"),
        "created_at": key_data.get("created_at", ""),
        "api_version": "1.0",
    }), 200


# ─── POST /api/v1/register ───────────────────────────────────────────────────

@app.route("/api/v1/register", methods=["POST"])
def api_register():
    """Register for a free API key."""
    # IP-based registration throttle: max 3 registrations per IP per 24h
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    reg_key = f"reg:{client_ip}"
    from database import get_request_count_today
    ip_reg_count = get_request_count_today(reg_key)
    if ip_reg_count >= 3:
        return jsonify({
            "error": "rate_limit_exceeded",
            "message": "Maximum 3 registrations per IP per day. Try again tomorrow.",
        }), 429

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

    # Track registration for IP throttle
    from database import increment_request_count
    increment_request_count(reg_key)

    return jsonify({
        "message": "API key created successfully. Store it safely — it cannot be recovered!",
        "api_key": raw_key,
        "tier": "free",
        "monthly_limit": TIER_LIMITS["free"]["monthly_limit"],
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


# ─── POST /api/v1/leads ──────────────────────────────────────────────────────

@app.route("/api/v1/leads", methods=["POST"])
def api_capture_lead():
    """Capture leads from Risk Score Widget (no auth required)."""
    # CORS for widget
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True)
    if not data or not data.get("email"):
        return jsonify({"error": "missing_email"}), 400

    email = data["email"].strip().lower()
    score = data.get("score", "?")
    lead_type = data.get("type", "unknown")
    timestamp = data.get("timestamp", "")

    # Store lead in SQLite
    try:
        from database import get_db
        with get_db() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS leads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    score TEXT,
                    lead_type TEXT,
                    source TEXT DEFAULT 'risk-score-widget',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )"""
            )
            conn.execute(
                "INSERT INTO leads (email, score, lead_type, created_at) VALUES (?, ?, ?, ?)",
                (email, str(score), lead_type, timestamp or None),
            )
    except Exception as e:
        return jsonify({"error": "storage_error", "message": str(e)}), 500

    return jsonify({"status": "captured", "message": "Thank you! Your report is on the way."}), 201


@app.route("/api/v1/admin/leads", methods=["GET"])
def admin_leads():
    """List captured leads (admin-only)."""
    token = request.headers.get("X-Admin-Token", "")
    if not token or token != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401

    try:
        from database import get_db
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM leads ORDER BY id DESC LIMIT 100"
            ).fetchall()
            leads = [dict(row) for row in rows]
        return jsonify({"leads": leads, "total": len(leads)}), 200
    except Exception:
        return jsonify({"leads": [], "total": 0}), 200


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
