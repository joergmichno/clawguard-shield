#!/usr/bin/env python3
"""
ClawGuard MCP Ecosystem Audit

Scans popular MCP server configurations for security issues.
Pulls tool descriptions from GitHub repos and runs ClawGuard MCP Scanner.

Usage:
    python mcp_audit.py                    # Scan all known servers
    python mcp_audit.py --output report    # Save results to mcp-audit-report.md
"""

import json
import os
import re
import sys
import subprocess
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_scanner import scan_mcp_config, format_mcp_report, format_mcp_json, MCPScanReport


@dataclass
class MCPServerInfo:
    """Info about an MCP server to scan."""
    name: str
    github: str
    description: str
    stars: int = 0
    tools: list = None  # Tool definitions to scan

    def __post_init__(self):
        if self.tools is None:
            self.tools = []


# Known popular MCP servers with their tool patterns
# Tool descriptions extracted from README/docs/source
KNOWN_SERVERS = [
    MCPServerInfo(
        name="filesystem",
        github="modelcontextprotocol/servers",
        description="Read/write access to local filesystem",
        stars=15000,
        tools=[
            {"name": "read_file", "description": "Read the complete contents of a file from the file system.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "Path to the file to read"}}}},
            {"name": "write_file", "description": "Create a new file or overwrite an existing file with new content.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "Path where the file should be written"}, "content": {"type": "string", "description": "Content to write to the file"}}}},
            {"name": "list_directory", "description": "Get a detailed listing of all files and directories in a specified path.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "Path of the directory to list"}}}},
            {"name": "move_file", "description": "Move or rename files and directories.", "inputSchema": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}}}},
            {"name": "search_files", "description": "Recursively search for files and directories matching a pattern.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "pattern": {"type": "string"}}}},
        ]
    ),
    MCPServerInfo(
        name="brave-search",
        github="modelcontextprotocol/servers",
        description="Web search via Brave Search API",
        stars=15000,
        tools=[
            {"name": "brave_web_search", "description": "Performs a web search using the Brave Search API.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "Search query"}}}},
            {"name": "brave_local_search", "description": "Searches for local businesses and places.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
        ]
    ),
    MCPServerInfo(
        name="github",
        github="modelcontextprotocol/servers",
        description="GitHub API integration for repos, issues, PRs",
        stars=15000,
        tools=[
            {"name": "create_or_update_file", "description": "Create or update a single file in a GitHub repository.", "inputSchema": {"type": "object", "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}, "path": {"type": "string"}, "content": {"type": "string"}}}},
            {"name": "push_files", "description": "Push multiple files to a GitHub repository in a single commit.", "inputSchema": {"type": "object", "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}, "files": {"type": "array"}}}},
            {"name": "create_issue", "description": "Create a new issue in a GitHub repository.", "inputSchema": {"type": "object", "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}, "title": {"type": "string"}, "body": {"type": "string"}}}},
        ]
    ),
    MCPServerInfo(
        name="puppeteer",
        github="modelcontextprotocol/servers",
        description="Browser automation with Puppeteer",
        stars=15000,
        tools=[
            {"name": "puppeteer_navigate", "description": "Navigate to a URL in the browser.", "inputSchema": {"type": "object", "properties": {"url": {"type": "string", "description": "URL to navigate to"}}}},
            {"name": "puppeteer_click", "description": "Click an element on the page using CSS selector.", "inputSchema": {"type": "object", "properties": {"selector": {"type": "string"}}}},
            {"name": "puppeteer_evaluate", "description": "Execute JavaScript in the browser console.", "inputSchema": {"type": "object", "properties": {"script": {"type": "string", "description": "JavaScript code to execute"}}}},
        ]
    ),
    MCPServerInfo(
        name="sqlite",
        github="modelcontextprotocol/servers",
        description="SQLite database interaction",
        stars=15000,
        tools=[
            {"name": "read_query", "description": "Execute a SELECT query on the SQLite database.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "SQL SELECT query to execute"}}}},
            {"name": "write_query", "description": "Execute an INSERT, UPDATE, or DELETE query on the SQLite database.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "SQL query to execute"}}}},
            {"name": "create_table", "description": "Create a new table in the SQLite database.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "CREATE TABLE SQL statement"}}}},
        ]
    ),
    MCPServerInfo(
        name="slack",
        github="modelcontextprotocol/servers",
        description="Slack workspace integration",
        stars=15000,
        tools=[
            {"name": "slack_post_message", "description": "Post a new message to a Slack channel.", "inputSchema": {"type": "object", "properties": {"channel_id": {"type": "string"}, "text": {"type": "string"}}}},
            {"name": "slack_reply_to_thread", "description": "Reply to a message thread in Slack.", "inputSchema": {"type": "object", "properties": {"channel_id": {"type": "string"}, "thread_ts": {"type": "string"}, "text": {"type": "string"}}}},
        ]
    ),
    MCPServerInfo(
        name="fetch",
        github="modelcontextprotocol/servers",
        description="HTTP request fetching for any URL",
        stars=15000,
        tools=[
            {"name": "fetch", "description": "Fetches a URL from the internet and extracts its contents as markdown.", "inputSchema": {"type": "object", "properties": {"url": {"type": "string", "description": "URL to fetch"}, "max_length": {"type": "integer"}, "raw": {"type": "boolean"}}}},
        ]
    ),
    MCPServerInfo(
        name="docker",
        github="ckreiling/mcp-server-docker",
        description="Docker container management via MCP",
        stars=500,
        tools=[
            {"name": "run_container", "description": "Run a new Docker container from an image.", "inputSchema": {"type": "object", "properties": {"image": {"type": "string", "description": "Docker image to run"}, "command": {"type": "string", "description": "Command to run in the container"}}}},
            {"name": "exec_container", "description": "Execute a command in a running Docker container.", "inputSchema": {"type": "object", "properties": {"container_id": {"type": "string"}, "command": {"type": "string", "description": "Any command to execute"}}}},
            {"name": "remove_container", "description": "Remove a Docker container.", "inputSchema": {"type": "object", "properties": {"container_id": {"type": "string"}}}},
        ]
    ),
    MCPServerInfo(
        name="shell",
        github="various",
        description="Direct shell command execution",
        stars=300,
        tools=[
            {"name": "run_command", "description": "Execute a shell command and return the output.", "inputSchema": {"type": "object", "properties": {"command": {"type": "string", "description": "Any shell command to execute"}}}},
        ]
    ),
    MCPServerInfo(
        name="postgres",
        github="modelcontextprotocol/servers",
        description="PostgreSQL database queries",
        stars=15000,
        tools=[
            {"name": "query", "description": "Run a read-only SQL query against the connected PostgreSQL database.", "inputSchema": {"type": "object", "properties": {"sql": {"type": "string", "description": "SQL query to execute"}}}},
        ]
    ),
]


def run_audit(servers=None, verbose=False):
    """Run security audit on known MCP servers."""
    if servers is None:
        servers = KNOWN_SERVERS

    results = []

    for server in servers:
        config = {
            "name": server.name,
            "tools": server.tools,
        }

        report = scan_mcp_config(config)
        results.append({
            "server": server,
            "report": report,
        })

        if verbose:
            print(f"\n{'='*50}")
            print(f"  {server.name} ({server.github})")
            print(f"  {server.description}")
            print(f"  Risk: {report.risk_score}/100 ({report.risk_level})")
            print(f"  Findings: {report.total_findings}")
            print(f"{'='*50}")

    return results


def generate_report(results, output_path=None):
    """Generate markdown report from audit results."""
    lines = []
    lines.append("# MCP Ecosystem Security Audit")
    lines.append(f"\n*Scanned by ClawGuard MCP Scanner v0.1.0*\n")
    lines.append(f"**Servers scanned:** {len(results)}")

    total_findings = sum(r["report"].total_findings for r in results)
    lines.append(f"**Total findings:** {total_findings}")

    critical = sum(1 for r in results if r["report"].risk_level == "CRITICAL")
    high = sum(1 for r in results if r["report"].risk_level == "HIGH")
    medium = sum(1 for r in results if r["report"].risk_level == "MEDIUM")
    low = sum(1 for r in results if r["report"].risk_level in ("LOW", "SAFE"))

    lines.append(f"**Risk distribution:** {critical} Critical, {high} High, {medium} Medium, {low} Low/Safe\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Server | Risk Score | Level | Findings | Key Risk |")
    lines.append("|--------|-----------|-------|----------|----------|")

    sorted_results = sorted(results, key=lambda r: r["report"].risk_score, reverse=True)

    for r in sorted_results:
        server = r["server"]
        report = r["report"]
        key_risk = "None"
        if report.findings:
            key_risk = report.findings[0].description[:50] + "..."
        elif report.injection_findings:
            key_risk = report.injection_findings[0].pattern_name
        else:
            key_risk = "Clean"

        lines.append(f"| {server.name} | {report.risk_score}/100 | {report.risk_level} | {report.total_findings} | {key_risk} |")

    # Detailed findings for risky servers
    lines.append("\n## Detailed Findings\n")

    for r in sorted_results:
        if r["report"].total_findings > 0:
            server = r["server"]
            report = r["report"]

            lines.append(f"### {server.name}")
            lines.append(f"- **Source:** [{server.github}](https://github.com/{server.github})")
            lines.append(f"- **Description:** {server.description}")
            lines.append(f"- **Risk Score:** {report.risk_score}/100 ({report.risk_level})")
            lines.append(f"- **Tools scanned:** {report.tools_scanned}\n")

            for f in report.findings:
                lines.append(f"**[{f.severity.value}] {f.risk.value}** — Tool: `{f.tool_name}`")
                lines.append(f"> {f.description}")
                lines.append(f"> Match: `{f.matched_text[:80]}`\n")

            for f in report.injection_findings:
                lines.append(f"**[{f.severity.value}] {f.pattern_name}**")
                lines.append(f"> {f.recommendation}\n")

            lines.append("---\n")

    # Recommendations
    lines.append("## Recommendations\n")
    lines.append("1. **MCP server authors** should audit tool descriptions for hidden instructions")
    lines.append("2. **MCP clients** (Claude, etc.) should scan tool descriptions before registration")
    lines.append("3. **Parameter validation** should restrict inputs to expected formats")
    lines.append("4. **Least privilege** — tools should request minimal permissions\n")

    report_text = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"Report saved to: {output_path}")

    return report_text


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ClawGuard MCP Ecosystem Audit")
    parser.add_argument("--output", default=None, help="Output markdown report path")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    results = run_audit(verbose=args.verbose)

    if args.json:
        json_results = []
        for r in results:
            json_results.append({
                "server": r["server"].name,
                "github": r["server"].github,
                "risk_score": r["report"].risk_score,
                "risk_level": r["report"].risk_level,
                "findings": r["report"].total_findings,
            })
        print(json.dumps(json_results, indent=2))
    else:
        report = generate_report(results, args.output)
        if not args.output:
            print(report)
