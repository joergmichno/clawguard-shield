# ClawGuard Shield

REST API for AI agent security scanning. Detects prompt injections, data exfiltration, dangerous commands, code obfuscation, and social engineering patterns.

[![Tests](https://img.shields.io/badge/tests-52%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Live](https://img.shields.io/badge/API-live-brightgreen)](https://prompttools.co/api/v1/health)

**Live API:** https://prompttools.co/api/v1/
**Landing Page:** https://prompttools.co/shield
**Core Scanner:** [ClawGuard](https://github.com/joergmichno/clawguard) (open-source, zero dependencies)

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
    "matched_text": "Ignore all previous instructions",
    "description": "BLOCK this input immediately."
  }],
  "scan_time_ms": 6
}
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/v1/` | - | API overview |
| `GET` | `/api/v1/health` | - | Health check |
| `POST` | `/api/v1/register` | - | Get free API key |
| `POST` | `/api/v1/scan` | API key | Scan text |
| `GET` | `/api/v1/patterns` | API key | List patterns |
| `GET` | `/api/v1/usage` | API key | Usage stats |

## What It Detects

- **Prompt Injection** — Direct overrides, role-play escapes, delimiter injection, synonym bypasses (EN + DE)
- **Dangerous Commands** — Shell commands, reverse shells, privilege escalation, remote code execution
- **Data Exfiltration** — API key leaks, private keys, passwords, database connection strings
- **Code Obfuscation** — Python eval/exec, getattr, magic attributes, string assembly
- **Social Engineering** — Urgency manipulation, authority impersonation, confidentiality traps

36+ regex patterns, 6ms average scan time, zero ML inference.

## Pricing

| Tier | Scans/Day | Max Text | Price |
|------|-----------|----------|-------|
| Free | 100 | 5,000 chars | Free |
| Pro | 10,000 | 50,000 chars | 9 EUR/mo |
| Enterprise | Unlimited | 200,000 chars | 49 EUR/mo |

## Self-Hosting

```bash
git clone https://github.com/joergmichno/clawguard-shield.git
cd clawguard-shield

# Docker
docker compose up -d --build

# Or locally
pip install -r requirements.txt
python app.py
```

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
# 52 passed
```

## Architecture

```
Flask API (app.py)
├── auth.py          # API key generation, hashing, validation
├── database.py      # SQLite schema + CRUD
├── rate_limiter.py  # Sliding-window rate limiting
├── models.py        # Request/Response dataclasses
└── clawguard.py     # Core scanner (from ClawGuard)
```

## Related Projects

- [ClawGuard](https://github.com/joergmichno/clawguard) — The open-source scanner this API wraps
- [Prompt Lab](https://github.com/joergmichno/prompt-lab) — Interactive prompt injection playground
- [DocQA](https://github.com/joergmichno/docqa) — RAG-based Q&A CLI

## License

MIT

---

Built by [Joerg Michno](https://github.com/joergmichno)
