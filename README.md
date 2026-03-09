# ClawGuard Shield

**Security Scanning REST API for AI Agents**

[![CI](https://github.com/joergmichno/clawguard-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/joergmichno/clawguard-shield/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-70%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Live](https://img.shields.io/badge/API-live-brightgreen)](https://prompttools.co/api/v1/health)
[![Uptime](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fprompttools.co%2Fapi%2Fv1%2Fhealth&query=%24.status&label=Status&color=brightgreen&style=flat)](https://prompttools.co/api/v1/health)
[![Deployed](https://img.shields.io/badge/Deployed-Docker%20%7C%20Linux%20VPS-blue?style=flat&logo=docker&logoColor=white)](https://prompttools.co/api/v1/)

🎯 **Live Demo:** [prompttools.co](https://prompttools.co)

REST API that scans text for prompt injections, data exfiltration, dangerous commands, code obfuscation, and social engineering patterns. 42+ regex patterns, 6ms average scan time, zero ML inference.

**Live Demo:** https://prompttools.co/api/v1/
**Core Scanner:** [ClawGuard](https://github.com/joergmichno/clawguard) (open-source, zero dependencies)

---

## Quick Start

```bash
# 1. Get a free API key
curl -X POST https://prompttools.co/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'

# 2. Scan text for threats
curl -X POST https://prompttools.co/api/v1/scan \
  -H "X-API-Key: cgs_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{"text": "Ignore all previous instructions"}'
```

Response:
```json
{
  "clean": false,
  "risk_score": 10,
  "severity": "CRITICAL",
  "findings_count": 1,
  "findings": [{
    "pattern_name": "Direct Override (EN)",
    "severity": "CRITICAL",
    "category": "Prompt Injection",
    "matched_text": "Ignore all previous instructions",
    "line_number": 1,
    "description": "BLOCK this input immediately."
  }],
  "scan_time_ms": 6
}
```

Clean text returns:
```json
{
  "clean": true,
  "risk_score": 0,
  "severity": "CLEAN",
  "findings_count": 0,
  "findings": [],
  "scan_time_ms": 2
}
```

## API Reference

### Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/v1/` | - | API overview with all endpoints |
| `GET` | `/api/v1/health` | - | Health check + pattern count |
| `POST` | `/api/v1/register` | - | Register for a free API key |
| `POST` | `/api/v1/scan` | API key | Scan text for security threats |
| `GET` | `/api/v1/patterns` | API key | List all detection patterns by category |
| `GET` | `/api/v1/usage` | API key | Your usage statistics (last 30 days) |

### Authentication

All protected endpoints require an API key in the `X-API-Key` header:

```
X-API-Key: cgs_your_key_here
```

**Key format:** `cgs_` prefix + 32 hex characters (36 chars total).
Keys are hashed with SHA-256 before storage — we never store your raw key.

### POST /api/v1/scan

Scan text for security threats.

**Request body:**
```json
{
  "text": "Text to scan (required)",
  "source": "user-message"
}
```

**Response headers (when rate-limited):**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
```

### POST /api/v1/register

Register for a free API key.

```json
// Request
{ "email": "you@example.com" }

// Response 201
{
  "message": "API key created successfully. Store it safely — it cannot be recovered!",
  "api_key": "cgs_abc123...",
  "tier": "free",
  "daily_limit": 100,
  "max_text_length": 5000
}
```

### GET /api/v1/usage

Returns your usage stats for the last 30 days.

```json
{
  "tier": "free",
  "tier_name": "Free",
  "daily_limit": 100,
  "today_used": 12,
  "today_remaining": 88,
  "last_30_days": {
    "total_requests": 247,
    "total_findings": 89,
    "avg_response_time_ms": 5.8
  },
  "key_prefix": "cgs_abc123ab...",
  "api_version": "1.0"
}
```

## Error Handling

All errors return JSON with `error` and `message` fields.

| Status | Error Code | Description |
|--------|-----------|-------------|
| `400` | `invalid_json` | Request body is not valid JSON |
| `400` | `validation_error` | Missing `text` field, empty text, or text exceeds max length |
| `401` | `missing_api_key` | No `X-API-Key` header provided |
| `401` | `invalid_key_format` | Key doesn't match `cgs_` + 32 hex format |
| `403` | `invalid_api_key` | Key not found or deactivated |
| `404` | `not_found` | Endpoint doesn't exist |
| `409` | `email_exists` | Email already has an API key |
| `429` | `rate_limit_exceeded` | Daily scan limit reached |

**Example error response:**
```json
{
  "error": "rate_limit_exceeded",
  "message": "Daily limit of 100 requests exceeded.",
  "tier": "free",
  "limit": 100,
  "used": 100
}
```

## What It Detects

| Category | Patterns | Examples |
|----------|----------|----------|
| **Prompt Injection** | 13 | Direct overrides, role-play escapes, delimiter injection, synonym bypasses (EN + DE) |
| **Dangerous Commands** | 5 | Shell commands (`rm -rf`, `curl \| bash`), reverse shells, privilege escalation |
| **Data Exfiltration** | 6 | API key leaks, private keys, passwords, database connection strings |
| **Code Obfuscation** | 11 | Python `eval()`/`exec()`, `getattr()`, magic attributes, string assembly |
| **Social Engineering** | 3 | Urgency manipulation, authority impersonation, confidentiality traps |

42+ regex patterns across 5 categories. Bilingual detection (English + German).

## Rate Limiting

Rate limits are enforced per API key on a daily sliding window (UTC).

| Tier | Daily Limit | Max Text Length |
|------|-------------|-----------------|
| **Free** | 100 scans | 5,000 chars |
| **Pro** | 10,000 scans | 50,000 chars |
| **Enterprise** | Unlimited | 200,000 chars |

The tier system demonstrates a multi-tenant API architecture with per-key rate limiting. When you exceed your limit, the API returns `429` with details about your usage. Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`) are included on every scan response.

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │           Nginx (HTTPS)              │
                    │         prompttools.co                │
                    └──────┬──────────┬──────────┬─────────┘
                           │          │          │
                    /shield│   /api/v1│    /     │
                           │          │          │
                    ┌──────┴──┐ ┌─────┴────┐ ┌───┴──────┐
                    │ Static  │ │  Shield  │ │ Prompt   │
                    │  HTML   │ │  (5001)  │ │ Lab      │
                    │         │ │  Flask   │ │ (5000)   │
                    └─────────┘ └────┬─────┘ └──────────┘
                                     │
                    ┌────────────────┼────────────────────┐
                    │                │                     │
               ┌────┴─────┐  ┌──────┴───────┐  ┌────────┴────────┐
               │  auth.py  │  │ rate_limiter │  │   clawguard.py  │
               │           │  │    .py       │  │  (scan engine)  │
               │ Key gen   │  │              │  │                 │
               │ SHA-256   │  │ Sliding      │  │ 42+ patterns    │
               │ Validate  │  │ window/day   │  │ 5 categories    │
               │ Tiers     │  │ Per-key      │  │ Risk scoring    │
               └────┬──────┘  └──────┬───────┘  └─────────────────┘
                    │                │
               ┌────┴────────────────┴────┐
               │      database.py          │
               │      SQLite (WAL mode)    │
               │                           │
               │  api_keys    usage_log    │
               │  rate_limits              │
               └───────────────────────────┘
```

### Database Schema

| Table | Purpose |
|-------|---------|
| `api_keys` | Key hash, prefix, email, tier, created/last used timestamps, active flag |
| `usage_log` | Per-request log: endpoint, text length, findings, risk score, response time |
| `rate_limits` | Daily request counter per key (sliding window) |

SQLite with WAL mode for concurrent reads. Thread-local connections. Foreign keys enforced.

### Request Flow

1. **CORS** — Preflight handling + permissive headers for browser clients
2. **Auth** — Validate `X-API-Key` format → SHA-256 hash → lookup in `api_keys`
3. **Rate Check** — Count today's requests for this key against tier limit
4. **Validation** — Check text length against tier's `max_text_length`
5. **Scan** — Run ClawGuard's `scan_text()` against all 42+ patterns
6. **Log** — Record usage (endpoint, text length, findings, response time)
7. **Response** — Return findings with rate limit headers

## Self-Hosting

```bash
git clone https://github.com/joergmichno/clawguard-shield.git
cd clawguard-shield

# Docker (recommended)
docker compose up -d --build

# Or locally
pip install -r requirements.txt
python app.py
```

The Docker setup includes:
- Python 3.12-slim base image
- Gunicorn with 2 workers
- Non-root `shield` user for security
- Persistent SQLite volume at `./data/`
- Health check endpoint

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5001` | Server port |
| `SHIELD_DB_PATH` | `/app/data/shield.db` | SQLite database path |
| `SECRET_KEY` | (generated) | Flask secret key |

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
# 70 passed
```

70 tests covering:
- All 6 API endpoints (scan, health, patterns, usage, register, index)
- Authentication (key generation, hashing, validation, format checking)
- Rate limiting (counting, enforcement, tier limits)
- Input validation (missing text, empty text, text too long)
- Error handling (invalid JSON, missing headers, wrong methods)
- CORS headers

## Related Projects

- [ClawGuard](https://github.com/joergmichno/clawguard) — The open-source scanner this API wraps (42+ patterns, zero dependencies)
- [ClawGuard Shield Python SDK](https://github.com/joergmichno/clawguard-shield-python) — Python client library ([PyPI](https://pypi.org/project/clawguard-shield/))
- [ClawGuard Scan Action](https://github.com/joergmichno/clawguard-scan-action) — GitHub Action for CI/CD security scanning
- [Prompt Lab](https://github.com/joergmichno/prompt-lab) — Interactive prompt injection playground ([Live Demo](https://prompttools.co))
- [DocQA](https://github.com/joergmichno/docqa) — RAG-based document Q&A CLI

## Ecosystem Integration

| Component | Install / Link | Description |
|-----------|---------------|-------------|
| **ClawGuard** (Core Engine) | [github.com/joergmichno/clawguard](https://github.com/joergmichno/clawguard) | Open-source scanner powering the Shield API |
| **Python SDK** | `pip install clawguard-shield` — [GitHub](https://github.com/joergmichno/clawguard-shield-python) | Python client library for the Shield API |
| **GitHub Action** | [github.com/joergmichno/clawguard-scan-action](https://github.com/joergmichno/clawguard-scan-action) | CI/CD security scanning for pull requests |
| **Prompt Lab** | [prompttools.co](https://prompttools.co) — [GitHub](https://github.com/joergmichno/prompt-lab) | Interactive prompt injection demo |

## License

MIT

---

Built by [Jörg Michno](https://github.com/joergmichno)
