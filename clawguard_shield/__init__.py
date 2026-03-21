"""
ClawGuard Shield — EU AI Act Compliance Scanner for AI Agents.

Usage:
    from clawguard_shield import scan_text, ScanReport, Finding, Severity

    report = scan_text("user input here")
    if report.risk_score > 0:
        print(f"Threats detected: {report.total_findings}")

(c) 2026 Jörg Michno
"""

__version__ = "0.5.0"

import sys
import os

# Add parent directory to path so we can import from clawguard.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawguard import (
    scan_text,
    ScanReport,
    Finding,
    Severity,
    ALL_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    DANGEROUS_COMMAND_PATTERNS,
    PYTHON_OBFUSCATION_PATTERNS,
    DATA_EXFILTRATION_PATTERNS,
    SOCIAL_ENGINEERING_PATTERNS,
    OUTPUT_INJECTION_PATTERNS,
    PII_DETECTION_PATTERNS,
    format_json,
    format_human,
)

__all__ = [
    "scan_text",
    "ScanReport",
    "Finding",
    "Severity",
    "ALL_PATTERNS",
    "PROMPT_INJECTION_PATTERNS",
    "DANGEROUS_COMMAND_PATTERNS",
    "PYTHON_OBFUSCATION_PATTERNS",
    "DATA_EXFILTRATION_PATTERNS",
    "SOCIAL_ENGINEERING_PATTERNS",
    "OUTPUT_INJECTION_PATTERNS",
    "PII_DETECTION_PATTERNS",
    "format_json",
    "format_human",
    "format_sarif",
]


def format_sarif(report: ScanReport) -> str:
    """Format scan results as SARIF v2.1.0 (Static Analysis Results Interchange Format).

    SARIF is the standard format for GitHub Code Scanning, GitLab SAST,
    and other CI/CD security tools.
    """
    import json

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ClawGuard Shield",
                        "version": __version__,
                        "informationUri": "https://prompttools.co/shield",
                        "rules": _build_sarif_rules(),
                    }
                },
                "results": _build_sarif_results(report),
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": report.timestamp,
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map ClawGuard severity to SARIF level."""
    return {
        "LOW": "note",
        "MEDIUM": "warning",
        "HIGH": "error",
        "CRITICAL": "error",
    }.get(severity.value, "warning")


def _build_sarif_rules() -> list:
    """Build SARIF rule definitions from all patterns."""
    rules = []
    seen_ids = set()
    for name, _pattern, severity, category, recommendation in ALL_PATTERNS:
        rule_id = name.replace(" ", "-").replace("(", "").replace(")", "")
        if rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)
        rules.append({
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": f"{category}: {name}"},
            "fullDescription": {"text": recommendation},
            "defaultConfiguration": {
                "level": _severity_to_sarif_level(severity),
            },
            "properties": {
                "category": category,
                "severity": severity.value,
            },
        })
    return rules


def _build_sarif_results(report: ScanReport) -> list:
    """Build SARIF results from scan findings."""
    results = []
    for finding in report.findings:
        rule_id = finding.pattern_name.replace(" ", "-").replace("(", "").replace(")", "")
        result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(finding.severity),
            "message": {
                "text": f"{finding.pattern_name}: {finding.matched_text}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": report.source,
                        },
                        "region": {
                            "startLine": max(finding.line_number, 1),
                            "snippet": {
                                "text": finding.context,
                            },
                        },
                    }
                }
            ],
            "properties": {
                "category": finding.category,
                "severity": finding.severity.value,
                "recommendation": finding.recommendation,
            },
        }
        results.append(result)
    return results
