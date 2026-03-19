#!/usr/bin/env python3
"""
ClawGuard Shield — HTML Benchmark Report Generator

Generates an interactive HTML dashboard from benchmark results.

Usage:
    python eval/report.py                    # Generate report
    python eval/report.py --open             # Generate and open in browser
"""

import sys
import os
import json
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.benchmark import load_test_cases, run_benchmark
from clawguard import scan_text


def collect_detailed_results(test_cases):
    """Run benchmark and collect per-case details."""
    results = []
    for tc in test_cases:
        report = scan_text(tc.input_text, source=f"eval:{tc.id}")
        detected = report.total_findings > 0

        if tc.expected_detection and detected:
            status = "TP"
        elif tc.expected_detection and not detected:
            status = "FN"
        elif not tc.expected_detection and detected:
            status = "FP"
        else:
            status = "TN"

        results.append({
            "id": tc.id,
            "status": status,
            "description": tc.description,
            "input_preview": tc.input_text[:80] + ("..." if len(tc.input_text) > 80 else ""),
            "expected": "DETECT" if tc.expected_detection else "PASS",
            "actual": "DETECT" if detected else "PASS",
            "findings": report.total_findings,
            "risk_score": report.risk_score,
            "tags": tc.tags,
            "category": tc.expected_category or "benign",
        })
    return results


def generate_html(benchmark_result, detailed_results):
    """Generate interactive HTML report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    r = benchmark_result

    # Count by tag
    tag_counts = {}
    for dr in detailed_results:
        for tag in dr["tags"]:
            if tag not in tag_counts:
                tag_counts[tag] = {"total": 0, "pass": 0, "fail": 0}
            tag_counts[tag]["total"] += 1
            if dr["status"] in ("TP", "TN"):
                tag_counts[tag]["pass"] += 1
            else:
                tag_counts[tag]["fail"] += 1

    failures = [d for d in detailed_results if d["status"] in ("FP", "FN")]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ClawGuard Shield — Benchmark Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0a0a0f; color: #e0e0e0; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
  .header {{ text-align: center; padding: 30px 0 20px; border-bottom: 1px solid #1a1a2e; margin-bottom: 30px; }}
  .header h1 {{ font-size: 28px; color: #00d4aa; margin-bottom: 8px; }}
  .header .subtitle {{ color: #888; font-size: 14px; }}
  .header .timestamp {{ color: #555; font-size: 12px; margin-top: 4px; }}

  .score-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
  .score-card {{ background: #12121a; border: 1px solid #1e1e30; border-radius: 12px; padding: 20px; text-align: center; }}
  .score-card .value {{ font-size: 36px; font-weight: 700; }}
  .score-card .label {{ font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .score-card.f1 .value {{ color: {('#00d4aa' if r.f1_score >= 0.95 else '#f0ad4e' if r.f1_score >= 0.8 else '#e74c3c')}; }}
  .score-card.precision .value {{ color: #3498db; }}
  .score-card.recall .value {{ color: #9b59b6; }}
  .score-card.total .value {{ color: #e0e0e0; }}

  .metrics-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 30px; }}
  .metric {{ background: #12121a; border: 1px solid #1e1e30; border-radius: 8px; padding: 14px; text-align: center; }}
  .metric .num {{ font-size: 24px; font-weight: 600; }}
  .metric .lbl {{ font-size: 11px; color: #888; margin-top: 2px; }}
  .metric.tp .num {{ color: #2ecc71; }}
  .metric.tn .num {{ color: #2ecc71; }}
  .metric.fp .num {{ color: #e74c3c; }}
  .metric.fn .num {{ color: #e74c3c; }}

  .section {{ margin-bottom: 30px; }}
  .section h2 {{ font-size: 18px; color: #00d4aa; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #1a1a2e; }}

  .category-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; }}
  .cat-card {{ background: #12121a; border: 1px solid #1e1e30; border-radius: 8px; padding: 14px; }}
  .cat-card .cat-name {{ font-size: 13px; font-weight: 600; margin-bottom: 8px; }}
  .cat-card .cat-bar {{ height: 6px; background: #1e1e30; border-radius: 3px; overflow: hidden; margin-bottom: 6px; }}
  .cat-card .cat-fill {{ height: 100%; border-radius: 3px; }}
  .cat-card .cat-stats {{ font-size: 11px; color: #888; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 10px 12px; background: #12121a; color: #888; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #1e1e30; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #0f0f18; }}
  tr:hover {{ background: #16161f; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge-tp {{ background: #0d3320; color: #2ecc71; }}
  .badge-tn {{ background: #0d3320; color: #2ecc71; }}
  .badge-fp {{ background: #3d1515; color: #e74c3c; }}
  .badge-fn {{ background: #3d1515; color: #e74c3c; }}
  .tag {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; background: #1e1e30; color: #888; margin-right: 3px; }}

  .filter-bar {{ margin-bottom: 16px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 6px 14px; border-radius: 6px; border: 1px solid #1e1e30; background: #12121a; color: #888; cursor: pointer; font-size: 12px; transition: all 0.2s; }}
  .filter-btn:hover, .filter-btn.active {{ background: #00d4aa; color: #0a0a0f; border-color: #00d4aa; }}

  .footer {{ text-align: center; padding: 20px; color: #444; font-size: 11px; border-top: 1px solid #1a1a2e; margin-top: 30px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>ClawGuard Shield</h1>
    <div class="subtitle">Benchmark Report — v0.4.0 (40 Patterns)</div>
    <div class="timestamp">{now} | {r.duration_ms}ms runtime | {r.total} test cases</div>
  </div>

  <div class="score-grid">
    <div class="score-card f1"><div class="value">{r.f1_score:.1%}</div><div class="label">F1 Score</div></div>
    <div class="score-card precision"><div class="value">{r.precision:.1%}</div><div class="label">Precision</div></div>
    <div class="score-card recall"><div class="value">{r.recall:.1%}</div><div class="label">Recall</div></div>
    <div class="score-card total"><div class="value">{r.total}</div><div class="label">Test Cases</div></div>
  </div>

  <div class="metrics-row">
    <div class="metric tp"><div class="num">{r.true_positives}</div><div class="lbl">True Positives</div></div>
    <div class="metric tn"><div class="num">{r.true_negatives}</div><div class="lbl">True Negatives</div></div>
    <div class="metric fp"><div class="num">{r.false_positives}</div><div class="lbl">False Positives</div></div>
    <div class="metric fn"><div class="num">{r.false_negatives}</div><div class="lbl">False Negatives</div></div>
  </div>

  <div class="section">
    <h2>Per-Category Performance</h2>
    <div class="category-grid">
"""

    cat_colors = {
        "PI": "#e74c3c", "DC": "#e67e22", "CO": "#9b59b6",
        "DE": "#3498db", "SE": "#f1c40f", "advanced": "#1abc9c",
        "adversarial": "#e74c3c", "attack": "#e74c3c", "benign": "#2ecc71"
    }

    for cat, scores in sorted(r.category_scores.items()):
        if cat in ("attack", "benign"):
            continue
        color = cat_colors.get(cat, "#00d4aa")
        f1_pct = scores["f1"] * 100
        html += f"""      <div class="cat-card">
        <div class="cat-name">{cat}</div>
        <div class="cat-bar"><div class="cat-fill" style="width:{f1_pct}%;background:{color}"></div></div>
        <div class="cat-stats">P={scores['precision']:.0%} R={scores['recall']:.0%} F1={scores['f1']:.0%} (n={scores['total']})</div>
      </div>
"""

    html += """    </div>
  </div>
"""

    # Failures section
    if failures:
        html += """  <div class="section">
    <h2>Failures</h2>
    <table>
      <tr><th>ID</th><th>Status</th><th>Description</th><th>Expected</th><th>Got</th><th>Tags</th></tr>
"""
        for f in failures:
            badge_class = f"badge-{f['status'].lower()}"
            tags_html = " ".join(f'<span class="tag">{t}</span>' for t in f["tags"])
            html += f"""      <tr>
        <td>{f['id']}</td>
        <td><span class="badge {badge_class}">{f['status']}</span></td>
        <td>{f['description']}</td>
        <td>{f['expected']}</td>
        <td>{f['actual']}</td>
        <td>{tags_html}</td>
      </tr>
"""
        html += "    </table>\n  </div>\n"

    # Full results table
    html += """  <div class="section">
    <h2>All Test Cases</h2>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterResults('all')">All</button>
      <button class="filter-btn" onclick="filterResults('TP')">TP</button>
      <button class="filter-btn" onclick="filterResults('TN')">TN</button>
      <button class="filter-btn" onclick="filterResults('FP')">FP</button>
      <button class="filter-btn" onclick="filterResults('FN')">FN</button>
    </div>
    <table id="results-table">
      <tr><th>ID</th><th>Status</th><th>Category</th><th>Description</th><th>Findings</th><th>Tags</th></tr>
"""

    for d in detailed_results:
        badge_class = f"badge-{d['status'].lower()}"
        tags_html = " ".join(f'<span class="tag">{t}</span>' for t in d["tags"])
        html += f"""      <tr data-status="{d['status']}">
        <td>{d['id']}</td>
        <td><span class="badge {badge_class}">{d['status']}</span></td>
        <td>{d['category']}</td>
        <td>{d['description']}</td>
        <td>{d['findings']}</td>
        <td>{tags_html}</td>
      </tr>
"""

    html += f"""    </table>
  </div>

  <div class="footer">
    ClawGuard Shield v0.4.0 — {r.total} patterns scanned in {r.duration_ms}ms — Generated {now}
  </div>
</div>

<script>
function filterResults(status) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#results-table tr[data-status]').forEach(row => {{
    row.style.display = (status === 'all' || row.dataset.status === status) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""
    return html


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ClawGuard Benchmark Report")
    parser.add_argument("--dataset", "-d",
                       default=os.path.join(os.path.dirname(__file__), "dataset.json"))
    parser.add_argument("--output", "-o",
                       default=os.path.join(os.path.dirname(__file__), "report.html"))
    parser.add_argument("--open", action="store_true", help="Open report in browser")
    args = parser.parse_args()

    print("Generating ClawGuard Benchmark Report...")

    cases = load_test_cases(args.dataset)
    result = run_benchmark(cases)
    details = collect_detailed_results(cases)
    html = generate_html(result, details)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report saved to: {args.output}")
    print(f"F1: {result.f1_score:.1%} | P: {result.precision:.1%} | R: {result.recall:.1%}")

    if args.open:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(args.output)}")
