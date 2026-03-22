# Contributing to ClawGuard Shield

Thanks for your interest in making AI agents more secure! ClawGuard uses deterministic regex-based pattern matching to detect prompt injections and other attacks against AI agents.

## Adding New Patterns

### Pattern Structure

Each pattern is a tuple with 5 elements:

```python
(
    "Pattern Name",                    # Unique, descriptive name
    r"(?i)(regex|pattern|here)",       # Python regex (raw string)
    Severity.HIGH,                     # LOW | MEDIUM | HIGH | CRITICAL
    "Category",                        # One of the 7 categories below
    "Recommendation text.",            # What to do when detected
)
```

### Categories

| Category | What it detects |
|---|---|
| `Prompt Injection` | Attempts to override system instructions |
| `Dangerous Commands` | Shell commands that could damage systems |
| `Code Obfuscation` | Hidden/encoded malicious payloads |
| `Data Exfiltration` | Attempts to leak sensitive data |
| `Social Engineering` | Manipulation via authority/urgency/emotion |
| `Output Injection` | XSS/SQL injection in agent outputs |
| `PII Detection` | Personal data (IBAN, credit cards, phone numbers) |

### Severity Guidelines

| Level | When to use | Score |
|---|---|---|
| `CRITICAL` | Direct system compromise, credential leak, active exfiltration | 10 |
| `HIGH` | Significant risk, requires immediate attention | 6 |
| `MEDIUM` | Moderate risk, should be reviewed | 3 |
| `LOW` | Minor concern, informational | 1 |

### Pattern Quality Checklist

Before submitting a pattern:

- [ ] Tested with `python -X utf8 eval/benchmark.py` (F1 must not drop below 97%)
- [ ] Added test cases to `eval/dataset.json` (at least 2 attacks + 1 benign)
- [ ] No ReDoS risk (test with 100k char input)
- [ ] Works case-insensitive where appropriate (`(?i)`)
- [ ] Supports both English and German variants where applicable
- [ ] Minimal false positives on normal text

### Adding Test Cases

Add entries to `eval/dataset.json`:

```json
{
    "text": "your attack text here",
    "expected": "attack",
    "category": "PI",
    "tags": ["attack", "your-tag"]
}
```

For benign (should NOT trigger):

```json
{
    "text": "normal text that should pass",
    "expected": "benign",
    "category": null,
    "tags": ["benign"]
}
```

### Category Codes

| Code | Full Name |
|---|---|
| `PI` | Prompt Injection |
| `DC` | Dangerous Commands |
| `CO` | Code Obfuscation |
| `DE` | Data Exfiltration |
| `SE` | Social Engineering |
| `OI` | Output Injection |
| `PII` | PII Detection |

## Running Tests

```bash
# Full benchmark (must show F1=100%)
python -X utf8 eval/benchmark.py

# Unit tests (must all pass)
python -X utf8 -m pytest tests/ -v

# Verbose benchmark with per-case details
python -X utf8 eval/benchmark.py --verbose

# Filter by category
python -X utf8 eval/benchmark.py --category PI
```

## Architecture

```
clawguard.py          # Core scanner engine + all patterns
eval/
  benchmark.py        # Precision/Recall/F1 measurement
  dataset.json        # 265 labeled test cases
  report.py           # HTML benchmark dashboard
  auto_improver.py    # Pattern optimization (experimental)
report_generator.py   # EU AI Act Compliance PDF reports
app.py                # Flask API server
tests/                # pytest test suite
```

## Code Style

- Python 3.10+
- Type hints where practical
- Docstrings for public functions
- `re.compile` for all patterns (performance)
- No external dependencies in the core scanner

## Questions?

Open an issue or reach out to joerg@prompttools.co.
