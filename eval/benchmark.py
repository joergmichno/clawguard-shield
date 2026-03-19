#!/usr/bin/env python3
"""
ClawGuard Shield — Evaluation Framework v1.0

Measures scanner accuracy against a labeled test dataset.
Foundation for systematic improvement (manual or auto-research).

Usage:
    python eval/benchmark.py                    # Run full benchmark
    python eval/benchmark.py --category PI      # Only Prompt Injection
    python eval/benchmark.py --verbose          # Show individual results
"""

import sys
import os
import json
import time
from dataclasses import dataclass
from typing import List, Optional

# Add parent dir to path for clawguard import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clawguard import scan_text, ScanReport


@dataclass
class TestCase:
    id: str
    input_text: str
    expected_detection: bool  # True = should be caught, False = benign
    expected_category: Optional[str]  # e.g. "Prompt Injection"
    expected_min_severity: Optional[str]  # e.g. "HIGH"
    description: str
    tags: List[str]


@dataclass
class BenchmarkResult:
    total: int
    true_positives: int   # Correctly detected attacks
    true_negatives: int   # Correctly passed benign inputs
    false_positives: int  # Benign flagged as attack
    false_negatives: int  # Attack missed
    precision: float
    recall: float
    f1_score: float
    duration_ms: float
    category_scores: dict


def load_test_cases(path: str) -> List[TestCase]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [TestCase(**tc) for tc in data["test_cases"]]


def run_benchmark(
    test_cases: List[TestCase],
    category_filter: Optional[str] = None,
    verbose: bool = False,
) -> BenchmarkResult:
    if category_filter:
        test_cases = [tc for tc in test_cases if category_filter in tc.tags]

    tp = fp = tn = fn = 0
    category_results = {}
    start = time.perf_counter()

    for tc in test_cases:
        report = scan_text(tc.input_text, source=f"eval:{tc.id}")
        detected = report.total_findings > 0

        # Track per-category
        for tag in tc.tags:
            if tag not in category_results:
                category_results[tag] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

        if tc.expected_detection and detected:
            tp += 1
            status = "TP"
            for tag in tc.tags:
                category_results[tag]["tp"] += 1
        elif tc.expected_detection and not detected:
            fn += 1
            status = "FN"
            for tag in tc.tags:
                category_results[tag]["fn"] += 1
        elif not tc.expected_detection and detected:
            fp += 1
            status = "FP"
            for tag in tc.tags:
                category_results[tag]["fp"] += 1
        else:
            tn += 1
            status = "TN"
            for tag in tc.tags:
                category_results[tag]["tn"] += 1

        if verbose:
            icon = {"TP": "✅", "TN": "✅", "FP": "❌", "FN": "❌"}[status]
            print(f"  {icon} [{status}] {tc.id}: {tc.description[:60]}")
            if status in ("FP", "FN"):
                print(f"       Expected: {'DETECT' if tc.expected_detection else 'PASS'}")
                print(f"       Got:      {'DETECT' if detected else 'PASS'} ({report.total_findings} findings)")

    duration = (time.perf_counter() - start) * 1000
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # Per-category F1
    cat_scores = {}
    for cat, r in category_results.items():
        p = r["tp"] / (r["tp"] + r["fp"]) if (r["tp"] + r["fp"]) > 0 else 0.0
        rec = r["tp"] / (r["tp"] + r["fn"]) if (r["tp"] + r["fn"]) > 0 else 0.0
        f = 2 * p * rec / (p + rec) if (p + rec) > 0 else 0.0
        cat_scores[cat] = {"precision": round(p, 3), "recall": round(rec, 3), "f1": round(f, 3), "total": r["tp"] + r["fp"] + r["tn"] + r["fn"]}

    return BenchmarkResult(
        total=total,
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        duration_ms=round(duration, 1),
        category_scores=cat_scores,
    )


def print_report(result: BenchmarkResult):
    print()
    print("=" * 60)
    print("  ClawGuard Shield — Benchmark Report")
    print("=" * 60)
    print(f"  Total test cases : {result.total}")
    print(f"  Duration         : {result.duration_ms}ms")
    print(f"  True Positives   : {result.true_positives}")
    print(f"  True Negatives   : {result.true_negatives}")
    print(f"  False Positives  : {result.false_positives}")
    print(f"  False Negatives  : {result.false_negatives}")
    print("-" * 60)
    print(f"  Precision : {result.precision:.1%}")
    print(f"  Recall    : {result.recall:.1%}")
    print(f"  F1 Score  : {result.f1_score:.1%}")
    print("-" * 60)

    if result.category_scores:
        print("  Per-Category:")
        for cat, scores in sorted(result.category_scores.items()):
            print(f"    {cat:25s}  P={scores['precision']:.0%}  R={scores['recall']:.0%}  F1={scores['f1']:.0%}  (n={scores['total']})")

    print("=" * 60)

    # Overall assessment
    if result.f1_score >= 0.9:
        print("  ✅ Excellent detection performance")
    elif result.f1_score >= 0.8:
        print("  🟡 Good, but room for improvement")
    elif result.f1_score >= 0.7:
        print("  🟠 Acceptable, needs tuning")
    else:
        print("  🔴 Below threshold — significant gaps")
    print("=" * 60)
    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ClawGuard Shield Benchmark")
    parser.add_argument("--category", "-c", help="Filter by category tag")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show individual results")
    parser.add_argument("--dataset", "-d", default=os.path.join(os.path.dirname(__file__), "dataset.json"), help="Test dataset path")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    cases = load_test_cases(args.dataset)
    result = run_benchmark(cases, category_filter=args.category, verbose=args.verbose)

    if args.json:
        print(json.dumps({
            "total": result.total,
            "tp": result.true_positives, "tn": result.true_negatives,
            "fp": result.false_positives, "fn": result.false_negatives,
            "precision": result.precision, "recall": result.recall,
            "f1_score": result.f1_score, "duration_ms": result.duration_ms,
            "category_scores": result.category_scores,
        }, indent=2))
    else:
        print_report(result)
