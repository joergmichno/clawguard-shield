"""ClawGuard Shield CLI — Scan files, directories, or stdin for security threats."""

import sys
import os
import argparse
import json

# Add parent directory to path for clawguard.py imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawguard import scan_text, format_human, format_json
from clawguard_shield import format_sarif, __version__


def scan_directory(path: str, extensions: tuple = (".txt", ".md", ".py", ".yaml", ".yml", ".json", ".prompt")) -> list:
    """Scan all matching files in a directory recursively."""
    from clawguard import ScanReport
    reports = []
    for root, _dirs, files in os.walk(path):
        for fname in sorted(files):
            if fname.endswith(extensions):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                    report = scan_text(text, source=fpath)
                    reports.append(report)
                except (PermissionError, OSError) as e:
                    print(f"Warning: Skipping {fpath}: {e}", file=sys.stderr)
    return reports


def main():
    # Fix emoji output on Windows
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        prog="clawguard",
        description="ClawGuard Shield — EU AI Act Compliance Scanner for AI Agents",
        epilog="(c) 2026 Jörg Michno. https://prompttools.co/shield",
    )
    parser.add_argument("target", nargs="?", help="File or directory to scan")
    parser.add_argument("--stdin", action="store_true", help="Read from standard input")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--sarif", action="store_true", help="Output as SARIF v2.1.0 (for GitHub Actions / CI)")
    parser.add_argument("--dir", metavar="PATH", help="Scan all files in directory recursively")
    parser.add_argument("--ext", metavar="EXT", help="File extensions to scan (comma-separated, default: .txt,.md,.py,.yaml,.yml,.json,.prompt)")
    parser.add_argument("--version", action="version", version=f"ClawGuard Shield v{__version__}")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only output if threats found")

    args = parser.parse_args()

    # Directory scan mode
    scan_dir = args.dir or (args.target if args.target and os.path.isdir(args.target) else None)
    if scan_dir:
        extensions = tuple(f".{e.strip('.')}" for e in args.ext.split(",")) if args.ext else (".txt", ".md", ".py", ".yaml", ".yml", ".json", ".prompt")
        reports = scan_directory(scan_dir, extensions)

        if not reports:
            print("No matching files found.", file=sys.stderr)
            sys.exit(2)

        # Aggregate results
        total_findings = sum(r.total_findings for r in reports)
        files_with_findings = [r for r in reports if r.total_findings > 0]

        if args.sarif:
            # Merge all findings into a single SARIF report
            merged = reports[0]
            merged.source = scan_dir
            for r in reports[1:]:
                merged.findings.extend(r.findings)
            merged.total_findings = len(merged.findings)
            merged.risk_score = min(10, sum(f.severity.score() for f in merged.findings))
            print(format_sarif(merged))
        elif args.json:
            data = {
                "clawguard_version": __version__,
                "scan_type": "directory",
                "directory": scan_dir,
                "files_scanned": len(reports),
                "files_with_findings": len(files_with_findings),
                "total_findings": total_findings,
                "reports": [json.loads(format_json(r)) for r in reports if r.total_findings > 0 or not args.quiet],
            }
            print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            print(f"\n  Scanned {len(reports)} files in {scan_dir}")
            print(f"  Findings: {total_findings} in {len(files_with_findings)} files\n")
            for r in reports:
                if r.total_findings > 0 or not args.quiet:
                    print(format_human(r))

        sys.exit(0 if total_findings == 0 else 1)

    # Single file or stdin
    if args.target and os.path.isfile(args.target):
        try:
            with open(args.target, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            source = args.target
        except FileNotFoundError:
            print(f"Error: File not found: {args.target}", file=sys.stderr)
            sys.exit(2)
        except PermissionError:
            print(f"Error: Permission denied: {args.target}", file=sys.stderr)
            sys.exit(2)
    elif args.stdin or not sys.stdin.isatty():
        text = sys.stdin.read()
        source = "stdin"
    else:
        parser.print_help()
        sys.exit(2)

    report = scan_text(text, source=source)

    if args.sarif:
        print(format_sarif(report))
    elif args.json:
        print(format_json(report))
    else:
        if not args.quiet or report.total_findings > 0:
            print(format_human(report))

    sys.exit(0 if report.total_findings == 0 else 1)


if __name__ == "__main__":
    main()
