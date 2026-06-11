#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from clawguard import scan_text

GH_API = "https://api.github.com"
GH_RAW = "https://raw.githubusercontent.com"
TIMEOUT = 10

SOURCE_GLOBS = [
    "server.py", "main.py", "index.ts", "index.js",
    "src/server.py", "src/main.py", "src/index.ts", "src/index.js",
]

# Patterns to extract tool descriptions from source code
DESC_PATTERNS = [
    # Python: description="..." or description='...'
    re.compile(r'description\s*=\s*"((?:[^"\\]|\\.)*)"'),
    re.compile(r"description\s*=\s*'((?:[^'\\]|\\.)*)'"),
    # TypeScript/JSON: description: "..." or "description": "..."
    re.compile(r'"?description"?\s*:\s*"((?:[^"\\]|\\.)*)"'),
    re.compile(r"'?description'?\s*:\s*'((?:[^'\\]|\\.)*)'"),
]


def parse_github_url(repo_url: str) -> tuple[str, str] | None:
    if not repo_url or "github.com" not in repo_url:
        return None
    parts = repo_url.rstrip("/").split("github.com/")[-1].split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None


def gh_get(url: str) -> requests.Response | None:
    try:
        resp = requests.get(url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=TIMEOUT)
        return resp if resp.status_code == 200 else None
    except (requests.RequestException, TimeoutError):
        return None


def fetch_readme(owner: str, repo: str) -> str | None:
    url = f"{GH_API}/repos/{owner}/{repo}/readme"
    try:
        resp = requests.get(url, headers={"Accept": "application/vnd.github.v3.raw"}, timeout=TIMEOUT)
        return resp.text if resp.status_code == 200 else None
    except (requests.RequestException, TimeoutError):
        return None


def fetch_file_tree(owner: str, repo: str) -> list[str]:
    resp = gh_get(f"{GH_API}/repos/{owner}/{repo}/git/trees/main?recursive=1")
    if not resp:
        resp = gh_get(f"{GH_API}/repos/{owner}/{repo}/git/trees/master?recursive=1")
    if not resp:
        return []
    tree = resp.json().get("tree", [])
    return [item["path"] for item in tree if item.get("type") == "blob"]


def find_source_files(file_tree: list[str]) -> list[str]:
    matches = []
    for glob in SOURCE_GLOBS:
        for path in file_tree:
            if path == glob or path.endswith(f"/{glob}"):
                matches.append(path)
    # Also grab any .py/.ts file directly in src/ that looks like a server
    for path in file_tree:
        if re.match(r'^src/[^/]+\.(py|ts|js)$', path) and path not in matches:
            matches.append(path)
    return matches[:10]  # cap to avoid hammering API


def fetch_raw_file(owner: str, repo: str, path: str, branch: str = "main") -> str | None:
    url = f"{GH_RAW}/{owner}/{repo}/{branch}/{path}"
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.text
        # try master
        url2 = f"{GH_RAW}/{owner}/{repo}/master/{path}"
        resp2 = requests.get(url2, timeout=TIMEOUT)
        return resp2.text if resp2.status_code == 200 else None
    except (requests.RequestException, TimeoutError):
        return None


def extract_descriptions(source: str) -> list[str]:
    descriptions = []
    for pattern in DESC_PATTERNS:
        for match in pattern.finditer(source):
            desc = match.group(1).strip()
            if len(desc) > 10:  # skip trivial matches like "name" or "id"
                descriptions.append(desc)
    return descriptions


def serialize_finding(f) -> dict:
    return {
        "severity": f.severity.value,
        "category": f.category,
        "pattern_name": f.pattern_name,
        "matched_text": f.matched_text[:200],
        "line_number": f.line_number,
        "recommendation": f.recommendation,
    }


def scan_repo_source(owner: str, repo: str) -> tuple[list[str], str]:
    """Scan source code for tool descriptions. Returns (descriptions, scan_mode_used)."""
    file_tree = fetch_file_tree(owner, repo)
    if not file_tree:
        return [], "no_tree"

    source_files = find_source_files(file_tree)
    if not source_files:
        return [], "no_source"

    all_descriptions = []
    for path in source_files:
        content = fetch_raw_file(owner, repo, path)
        if content:
            all_descriptions.extend(extract_descriptions(content))

    return all_descriptions, "source"


def scan_server(owner: str, repo: str, mode: str) -> dict | None:
    label = f"github:{owner}/{repo}"

    if mode == "source":
        descriptions, scan_mode = scan_repo_source(owner, repo)
        if descriptions:
            combined = "\n".join(descriptions)
            report = scan_text(combined, source=label)
            if report.total_findings > 0:
                return {
                    "finding_count": report.total_findings,
                    "risk_score": report.risk_score,
                    "scan_mode": "source",
                    "descriptions_found": len(descriptions),
                    "findings": [serialize_finding(f) for f in report.findings],
                }
            return None

        # Fallback to README if no descriptions extracted
        readme = fetch_readme(owner, repo)
        if not readme:
            return None
        report = scan_text(readme, source=label)
        if report.total_findings > 0:
            return {
                "finding_count": report.total_findings,
                "risk_score": report.risk_score,
                "scan_mode": "readme_fallback",
                "findings": [serialize_finding(f) for f in report.findings],
            }
        return None

    # mode == "readme"
    readme = fetch_readme(owner, repo)
    if not readme:
        return None
    report = scan_text(readme, source=label)
    if report.total_findings > 0:
        return {
            "finding_count": report.total_findings,
            "risk_score": report.risk_score,
            "scan_mode": "readme",
            "findings": [serialize_finding(f) for f in report.findings],
        }
    return None


def main():
    parser = argparse.ArgumentParser(description="Scan MCP server repos for security findings")
    parser.add_argument("--input", required=True, help="Path to scan-results.json")
    parser.add_argument("--output", default="advisory-targets.json", help="Output JSON path")
    parser.add_argument("--limit", type=int, default=50, help="Max repos to scan")
    parser.add_argument("--mode", choices=["source", "readme"], default="source",
                        help="Scan mode: source (tool descriptions) or readme (full README)")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    candidates = [
        s for s in data.get("results", [])
        if s.get("risk_level") == "medium"
        and s.get("repo_url")
        and parse_github_url(s.get("repo_url", ""))
    ][:args.limit]

    print(f"Scanning {len(candidates)} repos (mode: {args.mode}, limit: {args.limit})")

    results = []
    for i, server in enumerate(candidates, 1):
        name = server.get("name", "unknown")
        repo_url = server["repo_url"]
        owner, repo = parse_github_url(repo_url)

        result = scan_server(owner, repo, args.mode)
        if result:
            result["name"] = name
            result["repo_url"] = repo_url
            results.append(result)
            mode_tag = result.get("scan_mode", args.mode)
            print(f"  {i}/{len(candidates)}: {name} [{mode_tag}] {result['finding_count']} findings")
        else:
            print(f"  {i}/{len(candidates)}: {name} clean")

        time.sleep(1)

    output = {
        "scan_mode": args.mode,
        "scanned": len(candidates),
        "with_findings": len(results),
        "targets": results,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nDone. {len(results)}/{len(candidates)} servers with findings -> {args.output}")


if __name__ == "__main__":
    main()
