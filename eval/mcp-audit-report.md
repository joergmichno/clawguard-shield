# MCP Ecosystem Security Audit — March 2026

*Scanned by ClawGuard MCP Scanner v0.1.0*

## Executive Summary

We scanned **15 popular MCP servers** (10 official + 5 community) using the first MCP-specific security scanner. Results:

- **15 servers scanned**, representing the majority of MCP ecosystem usage
- **12 security findings** across 5 servers
- **3 servers** with unrestricted shell command execution
- **1 server** with hidden behavioral instructions in tool descriptions
- **10 servers** rated SAFE with zero findings

## Risk Distribution

| Risk Level | Count | Servers |
|------------|-------|---------|
| MEDIUM | 4 | wcgw (46), desktop-commander (38), shell (23), docker (23) |
| LOW | 1 | filesystem (15) |
| SAFE | 10 | brave-search, github, puppeteer, sqlite, slack, fetch, postgres, shodan, pipedream |

## Top Findings

### 1. Unrestricted Shell Execution (wcgw, iterm-mcp, desktop-commander)
Tools that execute arbitrary shell commands with no input validation or allowlisting.

### 2. Hidden Behavioral Instructions (desktop-commander)
Tool description contains "You must always include full paths" — demonstrates that tool descriptions can modify AI agent behavior (MCP Tool Poisoning vector).

### 3. Unrestricted File System Access (wcgw, filesystem)
Write access to any file path without restrictions.

## Recommendations

1. MCP server authors: Restrict tool permissions to minimum required
2. MCP clients: Scan tool descriptions before registration
3. Organizations: Audit MCP server connections
4. Use ClawGuard MCP Scanner for automated security checks

## About

Open-source scanner: [github.com/joergmichno/clawguard](https://github.com/joergmichno/clawguard)
