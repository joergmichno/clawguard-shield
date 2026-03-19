#!/usr/bin/env python3
"""
ClawGuard Shield — Auto-Improver v0.1 (Karpathy-inspired Hill Climbing)

Uses an LLM to propose regex mutations, tests them against the benchmark,
and keeps only improvements. Simple hill climbing on F1 score.

Usage:
    python eval/auto_improver.py                      # Run with defaults
    python eval/auto_improver.py --iterations 20      # More iterations
    python eval/auto_improver.py --dry-run             # Show proposals without applying
"""

import sys
import os
import re
import json
import copy
import time
from typing import Optional

# Add parent dir for clawguard import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.benchmark import load_test_cases, run_benchmark


def get_current_patterns():
    """Extract all regex patterns from clawguard.py source."""
    clawguard_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "clawguard.py")
    with open(clawguard_path, "r", encoding="utf-8") as f:
        source = f.read()

    # Find all pattern definitions: r"..." in pattern tuples
    pattern_regex = re.compile(r'r"((?:[^"\\]|\\.)*)"', re.DOTALL)
    matches = pattern_regex.findall(source)
    return matches, source, clawguard_path


def get_failing_cases(dataset_path: str) -> dict:
    """Run benchmark and return failing test cases grouped by type."""
    cases = load_test_cases(dataset_path)
    result = run_benchmark(cases, verbose=False)

    # Re-run to identify specific failures
    from clawguard import scan_text
    failures = {"false_negatives": [], "false_positives": []}

    for tc in cases:
        report = scan_text(tc.input_text, source=f"eval:{tc.id}")
        detected = report.total_findings > 0

        if tc.expected_detection and not detected:
            failures["false_negatives"].append({
                "id": tc.id,
                "input": tc.input_text,
                "category": tc.expected_category,
                "description": tc.description,
                "tags": tc.tags,
            })
        elif not tc.expected_detection and detected:
            failures["false_positives"].append({
                "id": tc.id,
                "input": tc.input_text,
                "description": tc.description,
                "tags": tc.tags,
            })

    return {
        "baseline": {
            "f1": result.f1_score,
            "precision": result.precision,
            "recall": result.recall,
            "total": result.total,
            "fp": result.false_positives,
            "fn": result.false_negatives,
        },
        "failures": failures,
    }


def generate_improvement_prompt(failures: dict, patterns: list) -> str:
    """Generate a prompt for the LLM to propose pattern improvements."""
    fn_list = failures["failures"]["false_negatives"]
    fp_list = failures["failures"]["false_positives"]

    prompt = f"""You are a regex security expert improving a prompt injection scanner.

Current performance: F1={failures['baseline']['f1']}, {failures['baseline']['fn']} false negatives, {failures['baseline']['fp']} false positives.

FALSE NEGATIVES (attacks that were MISSED):
"""
    for fn in fn_list:
        prompt += f"- [{fn['id']}] {fn['description']}: {repr(fn['input'][:100])}\n"

    if fp_list:
        prompt += "\nFALSE POSITIVES (benign inputs wrongly flagged):\n"
        for fp in fp_list:
            prompt += f"- [{fp['id']}] {fp['description']}: {repr(fp['input'][:100])}\n"

    prompt += f"""
Current pattern count: {len(patterns)}

Propose UP TO 3 new regex patterns or modifications to catch the false negatives
WITHOUT introducing false positives. For each proposal:
1. Pattern name
2. Regex (Python re syntax)
3. Category (Prompt Injection, Dangerous Commands, Code Obfuscation, Data Exfiltration, Social Engineering)
4. Severity (LOW, MEDIUM, HIGH, CRITICAL)
5. Brief explanation

Output as JSON array:
[{{"name": "...", "regex": "...", "category": "...", "severity": "...", "explanation": "..."}}]

RULES:
- Patterns must be valid Python regex
- Avoid catastrophic backtracking (no nested quantifiers on overlapping sets)
- Be specific enough to avoid false positives on normal text
- Consider both English and German inputs
"""
    return prompt


def print_report(failures: dict):
    """Print current state report."""
    b = failures["baseline"]
    print(f"\n{'='*60}")
    print(f"  Auto-Improver — Current State")
    print(f"{'='*60}")
    print(f"  F1: {b['f1']:.1%}  |  Precision: {b['precision']:.1%}  |  Recall: {b['recall']:.1%}")
    print(f"  FP: {b['fp']}  |  FN: {b['fn']}  |  Total: {b['total']}")
    print(f"{'='*60}")

    if failures["failures"]["false_negatives"]:
        print(f"\n  Remaining False Negatives:")
        for fn in failures["failures"]["false_negatives"]:
            print(f"    - [{fn['id']}] {fn['description']}")

    if failures["failures"]["false_positives"]:
        print(f"\n  Remaining False Positives:")
        for fp in failures["failures"]["false_positives"]:
            print(f"    - [{fp['id']}] {fp['description']}")

    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ClawGuard Auto-Improver")
    parser.add_argument("--dataset", "-d",
                       default=os.path.join(os.path.dirname(__file__), "dataset.json"))
    parser.add_argument("--dry-run", action="store_true",
                       help="Analyze failures and generate LLM prompt without applying")
    args = parser.parse_args()

    print("\n  ClawGuard Auto-Improver v0.1")
    print("  Karpathy-inspired Hill Climbing on F1\n")

    # Step 1: Analyze current state
    print("  [1/3] Analyzing current performance...")
    failures = get_failing_cases(args.dataset)
    print_report(failures)

    if failures["baseline"]["fn"] == 0 and failures["baseline"]["fp"] == 0:
        print("  Nothing to improve — perfect score!")
        sys.exit(0)

    # Step 2: Extract patterns
    print("  [2/3] Extracting current patterns...")
    patterns, source, path = get_current_patterns()
    print(f"  Found {len(patterns)} regex patterns in clawguard.py")

    # Step 3: Generate improvement prompt
    print("  [3/3] Generating improvement prompt...")
    prompt = generate_improvement_prompt(failures, patterns)

    if args.dry_run:
        print("\n  === DRY RUN — LLM Prompt ===\n")
        print(prompt)
        print("\n  Copy this prompt to an LLM to get pattern proposals.")
        print("  Then manually add the best patterns to clawguard.py")
        print("  and re-run the benchmark to verify improvement.\n")
    else:
        # In v0.2: Call LLM API directly
        print("\n  === LLM Prompt (manual mode) ===\n")
        print(prompt)
        print("\n  v0.1 = Manual mode. Feed this to Claude/GPT and apply suggestions.")
        print("  v0.2 will call the Anthropic API directly for autonomous improvement.\n")

    # Save prompt to file for reference
    prompt_path = os.path.join(os.path.dirname(__file__), "last_improvement_prompt.txt")
    with open(prompt_path, "w", encoding="utf-8") as f:
        f.write(prompt)
    print(f"  Prompt saved to: {prompt_path}")
