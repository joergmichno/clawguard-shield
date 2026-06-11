"""
ClawGuard MCP Server — Streamable HTTP Transport

Exposes ClawGuard scanning as MCP tools via JSON-RPC 2.0.
Endpoint: POST /api/v1/mcp

Tools:
    scan_text       — Scan text for prompt injection / jailbreak
    scan_mcp_config — Scan MCP server config for security issues
"""

import json
from flask import Blueprint, request, jsonify
from clawguard import scan_text as cg_scan_text, ALL_PATTERNS, Severity
from mcp_scanner import scan_mcp_config, format_mcp_json

mcp_bp = Blueprint("mcp", __name__)

PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {
    "name": "clawguard",
    "version": "0.7.3",
}

TOOLS = [
    {
        "name": "scan_text",
        "description": "Scan text for prompt injection attacks, jailbreak attempts, and other AI security threats. Detects 204+ attack patterns across 15 languages. Returns findings with severity, confidence, and remediation advice.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to scan for security threats",
                },
                "source": {
                    "type": "string",
                    "description": "Optional label for the source (e.g. 'user-input', 'email', 'tool-description')",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "scan_mcp_config",
        "description": "Scan an MCP server configuration for security vulnerabilities: tool poisoning, permission escalation, data exfiltration vectors, hidden instructions, and prompt injection in tool descriptions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "description": "MCP config JSON with a 'tools' array, or Claude Desktop format with 'mcpServers'",
                },
            },
            "required": ["config"],
        },
    },
]


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _jsonrpc_ok(req_id, result):
    return jsonify({"jsonrpc": "2.0", "id": req_id, "result": result})


def _jsonrpc_err(req_id, code, message):
    return jsonify(
        {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
    )


# ─── Tool handlers ───────────────────────────────────────────────────────────


def _handle_scan_text(arguments):
    text = arguments.get("text", "")
    source = arguments.get("source", "mcp-client")

    if not text:
        return {"content": [{"type": "text", "text": "Error: 'text' is required."}], "isError": True}

    result = cg_scan_text(text, source=source)

    findings = []
    for f in result.findings:
        findings.append(
            {
                "severity": f.severity.value,
                "pattern_name": f.pattern_name,
                "matched_text": f.matched_text[:200],
                "confidence": f.confidence,
                "recommendation": f.recommendation,
            }
        )

    risk_score = min(
        sum(
            30 if f["severity"] == "CRITICAL"
            else 20 if f["severity"] == "HIGH"
            else 10 if f["severity"] == "MEDIUM"
            else 5
            for f in findings
        ),
        100,
    )

    output = {
        "threat_detected": len(findings) > 0,
        "findings_count": len(findings),
        "risk_score": risk_score,
        "findings": findings,
    }

    return {"content": [{"type": "text", "text": json.dumps(output, indent=2)}]}


def _handle_scan_mcp_config(arguments):
    config = arguments.get("config", {})

    if not config:
        return {"content": [{"type": "text", "text": "Error: 'config' is required."}], "isError": True}

    report = scan_mcp_config(config)
    result = format_mcp_json(report)

    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


TOOL_HANDLERS = {
    "scan_text": _handle_scan_text,
    "scan_mcp_config": _handle_scan_mcp_config,
}


# ─── MCP Endpoint ────────────────────────────────────────────────────────────


@mcp_bp.route("/api/v1/mcp", methods=["POST"])
def mcp_endpoint():
    """MCP Streamable HTTP endpoint — JSON-RPC 2.0."""
    body = request.get_json(silent=True)
    if not body:
        return _jsonrpc_err(None, -32700, "Parse error: invalid JSON"), 400

    method = body.get("method")
    req_id = body.get("id")
    params = body.get("params", {})

    # ── initialize ──
    if method == "initialize":
        return _jsonrpc_ok(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        )

    # ── notifications (no response) ──
    if method == "notifications/initialized":
        return "", 204

    # ── ping ──
    if method == "ping":
        return _jsonrpc_ok(req_id, {})

    # ── tools/list ──
    if method == "tools/list":
        return _jsonrpc_ok(req_id, {"tools": TOOLS})

    # ── tools/call ──
    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return _jsonrpc_err(req_id, -32601, f"Unknown tool: {tool_name}")

        try:
            result = handler(arguments)
        except Exception as e:
            return _jsonrpc_ok(
                req_id,
                {"content": [{"type": "text", "text": f"Error: {str(e)}"}], "isError": True},
            )

        return _jsonrpc_ok(req_id, result)

    # ── unknown method ──
    return _jsonrpc_err(req_id, -32601, f"Method not found: {method}")
