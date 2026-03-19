#!/usr/bin/env python3
"""Export ClawGuard patterns to YAML for external configuration and community contributions."""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawguard import (
    PROMPT_INJECTION_PATTERNS,
    DANGEROUS_COMMAND_PATTERNS,
    PYTHON_OBFUSCATION_PATTERNS,
    DATA_EXFILTRATION_PATTERNS,
    SOCIAL_ENGINEERING_PATTERNS,
    OUTPUT_INJECTION_PATTERNS,
    PII_DETECTION_PATTERNS,
)


def patterns_to_dict(patterns, group_name):
    """Convert pattern tuples to dict structure."""
    result = []
    for name, regex, severity, category, recommendation in patterns:
        result.append({
            "name": name,
            "regex": regex,
            "severity": severity.value,
            "category": category,
            "recommendation": recommendation,
        })
    return result


def export_yaml(output_path=None):
    """Export all patterns as YAML."""
    groups = {
        "prompt_injection": patterns_to_dict(PROMPT_INJECTION_PATTERNS, "Prompt Injection"),
        "dangerous_commands": patterns_to_dict(DANGEROUS_COMMAND_PATTERNS, "Dangerous Commands"),
        "python_obfuscation": patterns_to_dict(PYTHON_OBFUSCATION_PATTERNS, "Python Obfuscation"),
        "data_exfiltration": patterns_to_dict(DATA_EXFILTRATION_PATTERNS, "Data Exfiltration"),
        "social_engineering": patterns_to_dict(SOCIAL_ENGINEERING_PATTERNS, "Social Engineering"),
        "output_injection": patterns_to_dict(OUTPUT_INJECTION_PATTERNS, "Output Injection"),
        "pii_detection": patterns_to_dict(PII_DETECTION_PATTERNS, "PII Detection"),
    }

    # Build YAML manually (no PyYAML dependency needed)
    lines = [
        "# ClawGuard Shield v0.5.0 — Pattern Database",
        "# (c) 2026 Jörg Michno | https://prompttools.co/shield",
        "#",
        "# Format: Each pattern has name, regex, severity (LOW/MEDIUM/HIGH/CRITICAL),",
        "#         category, and recommendation.",
        "#",
        "# To add custom patterns: Copy this file to clawguard.yaml in your project root",
        "# and add/modify patterns. Run: clawguard --config clawguard.yaml --dir .",
        "",
        f"version: \"0.5.0\"",
        f"total_patterns: {sum(len(v) for v in groups.values())}",
        "",
    ]

    for group_name, patterns in groups.items():
        lines.append(f"{group_name}:")
        for p in patterns:
            lines.append(f"  - name: \"{p['name']}\"")
            # Escape regex for YAML (use literal block for complex regexes)
            regex = p['regex']
            if '"' in regex or len(regex) > 100:
                lines.append(f"    regex: |")
                lines.append(f"      {regex}")
            else:
                lines.append(f"    regex: \"{regex}\"")
            lines.append(f"    severity: {p['severity']}")
            lines.append(f"    category: \"{p['category']}\"")
            lines.append(f"    recommendation: \"{p['recommendation']}\"")
            lines.append("")

    output = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Exported {sum(len(v) for v in groups.values())} patterns to {output_path}")
    else:
        print(output)


def export_json(output_path=None):
    """Export all patterns as JSON (for programmatic use)."""
    groups = {
        "version": "0.5.0",
        "prompt_injection": patterns_to_dict(PROMPT_INJECTION_PATTERNS, "Prompt Injection"),
        "dangerous_commands": patterns_to_dict(DANGEROUS_COMMAND_PATTERNS, "Dangerous Commands"),
        "python_obfuscation": patterns_to_dict(PYTHON_OBFUSCATION_PATTERNS, "Python Obfuscation"),
        "data_exfiltration": patterns_to_dict(DATA_EXFILTRATION_PATTERNS, "Data Exfiltration"),
        "social_engineering": patterns_to_dict(SOCIAL_ENGINEERING_PATTERNS, "Social Engineering"),
        "output_injection": patterns_to_dict(OUTPUT_INJECTION_PATTERNS, "Output Injection"),
        "pii_detection": patterns_to_dict(PII_DETECTION_PATTERNS, "PII Detection"),
    }

    output = json.dumps(groups, indent=2, ensure_ascii=False)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Exported {sum(len(v) for v in groups.values() if isinstance(v, list))} patterns to {output_path}")
    else:
        print(output)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Export ClawGuard patterns")
    parser.add_argument("--format", choices=["yaml", "json"], default="yaml")
    parser.add_argument("--output", "-o", help="Output file path")
    args = parser.parse_args()

    if args.format == "yaml":
        export_yaml(args.output)
    else:
        export_json(args.output)
