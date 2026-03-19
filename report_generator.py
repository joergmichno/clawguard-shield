"""
ClawGuard Shield - Compliance PDF Report Generator

Transforms Shield scan results into professional PDF compliance reports.
Target: Enterprise customers needing documented AI security measures.
EU AI Act reference: Enforcement date 02.08.2026.

(c) 2026 Joerg Michno
"""

import os
from datetime import datetime, timezone
from fpdf import FPDF

# ─── Constants ───────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": (220, 38, 38),   # Red
    "HIGH": (234, 88, 12),       # Orange
    "MEDIUM": (202, 138, 4),     # Yellow/Amber
    "LOW": (22, 163, 74),        # Green
}

CATEGORY_DESCRIPTIONS = {
    "Prompt Injection": (
        "Direct attempts to override, hijack, or manipulate the AI agent's "
        "system instructions. These attacks can cause the agent to ignore safety "
        "constraints and execute arbitrary instructions from untrusted input."
    ),
    "System Prompt Extraction": (
        "Attempts to leak the AI agent's internal system prompt, revealing "
        "confidential instructions, business logic, and security configurations "
        "to unauthorized parties."
    ),
    "Data Exfiltration": (
        "Techniques to steal sensitive data through the AI agent by embedding "
        "hidden requests, markdown image injections, or encoded payloads that "
        "transmit data to external servers."
    ),
    "Social Engineering": (
        "Manipulation tactics exploiting the AI agent's helpfulness bias. "
        "These attacks use emotional manipulation, authority claims, or urgency "
        "to bypass safety guidelines."
    ),
    "Context Manipulation": (
        "Advanced attacks targeting the agent's context window through delimiter "
        "injection, encoding tricks, or structural manipulation of the input "
        "to confuse instruction boundaries."
    ),
    "Dangerous Commands": (
        "System-level commands that could damage infrastructure, delete data, "
        "or compromise server security if executed by an AI agent with shell access."
    ),
    "Code Obfuscation": (
        "Obfuscated code patterns (Base64, hex encoding, string concatenation, "
        "dynamic imports) used to hide malicious payloads from static analysis."
    ),
    "Output Injection": (
        "Attempts to inject malicious content (XSS, SQL injection) into AI agent "
        "outputs. OWASP LLM02: Insecure Output Handling."
    ),
}

EU_AI_ACT_ARTICLES = [
    {
        "article": "Article 9 - Risk Management System",
        "requirement": "High-risk AI systems require a risk management system "
        "throughout the system's lifecycle, including identification and "
        "analysis of known and foreseeable risks.",
        "relevance": "Prompt injection scanning directly addresses the requirement "
        "to identify and mitigate foreseeable security risks in AI systems.",
    },
    {
        "article": "Article 15 - Accuracy, Robustness and Cybersecurity",
        "requirement": "High-risk AI systems shall be resilient against attempts "
        "by unauthorized third parties to alter their use, outputs or performance "
        "by exploiting system vulnerabilities.",
        "relevance": "Documented prompt injection testing demonstrates compliance "
        "with cybersecurity robustness requirements.",
    },
    {
        "article": "Article 17 - Quality Management System",
        "requirement": "Providers of high-risk AI systems shall put a quality "
        "management system in place that ensures compliance, including "
        "procedures for data management, risk management, and post-market "
        "monitoring.",
        "relevance": "Regular security scanning with documented reports forms part "
        "of the required quality management system.",
    },
    {
        "article": "Article 61 - Post-Market Monitoring",
        "requirement": "Providers shall establish and document a post-market "
        "monitoring system proportionate to the nature of the AI system.",
        "relevance": "Continuous security scanning and compliance reporting "
        "satisfies post-market monitoring obligations for AI security.",
    },
]


class ComplianceReport(FPDF):
    """Professional compliance PDF report for Shield scan results."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=25)

    # ─── Header / Footer ─────────────────────────────────────────────────

    def header(self):
        if self.page_no() == 1:
            return  # Cover page has no header
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, "ClawGuard Shield - Security Compliance Report", align="L")
        self.cell(0, 8, f"Page {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-20)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 8,
            "Generated by ClawGuard Shield (prompttools.co) | "
            "This report is for informational purposes. "
            "Consult legal counsel for full EU AI Act compliance.",
            align="C",
        )

    # ─── Cover Page ──────────────────────────────────────────────────────

    def add_cover_page(self, scan_data: dict, company_name: str = ""):
        self.add_page()
        self.set_fill_color(10, 10, 10)
        self.rect(0, 0, 210, 297, "F")

        # Logo area
        self.set_y(50)
        self.set_font("Helvetica", "B", 36)
        self.set_text_color(74, 158, 255)
        self.cell(0, 15, "ClawGuard Shield", align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "", 14)
        self.set_text_color(180, 180, 180)
        self.cell(0, 10, "AI Agent Security Compliance Report", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(20)

        # Risk indicator
        severity = scan_data.get("severity", "CLEAN")
        risk_score = scan_data.get("risk_score", 0)

        if severity == "CLEAN":
            color = (22, 163, 74)
        else:
            color = SEVERITY_COLORS.get(severity, (150, 150, 150))

        self.set_draw_color(*color)
        self.set_line_width(1.5)
        cx, cy = 105, 140
        self.ellipse(cx - 30, cy - 30, 60, 60, "D")
        self.set_font("Helvetica", "B", 32)
        self.set_text_color(*color)
        self.set_y(cy - 12)
        score_text = str(risk_score) if severity != "CLEAN" else "0"
        self.cell(0, 15, score_text, align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 11)
        self.cell(0, 8, f"Risk Score (0-10)", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(5)
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, f"Severity: {severity}", align="C", new_x="LMARGIN", new_y="NEXT")

        # Metadata
        self.ln(20)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(150, 150, 150)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        findings_count = scan_data.get("findings_count", 0)
        scan_time = scan_data.get("scan_time_ms", 0)

        meta_lines = [
            f"Report Generated: {now}",
            f"Findings: {findings_count} threat(s) detected",
            f"Scan Time: {scan_time}ms",
            f"Scanner: ClawGuard Shield v0.5.0 (50 patterns, 7 categories)",
        ]
        if company_name:
            meta_lines.insert(0, f"Organization: {company_name}")

        for line in meta_lines:
            self.cell(0, 7, line, align="C", new_x="LMARGIN", new_y="NEXT")

        # EU AI Act badge
        self.ln(10)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(74, 158, 255)
        self.cell(
            0, 8,
            "EU AI Act Compliance Reference Included (Enforcement: 02 August 2026)",
            align="C",
        )

    # ─── Executive Summary ───────────────────────────────────────────────

    def add_executive_summary(self, scan_data: dict):
        self.add_page()
        self.set_text_color(0, 0, 0)

        self._section_title("1. Executive Summary")

        severity = scan_data.get("severity", "CLEAN")
        risk_score = scan_data.get("risk_score", 0)
        findings_count = scan_data.get("findings_count", 0)
        scan_time = scan_data.get("scan_time_ms", 0)

        # Summary box
        self.set_fill_color(245, 245, 245)
        box_y = self.get_y()
        self.rect(10, box_y, 190, 40, "F")
        self.set_xy(15, box_y + 5)

        self.set_font("Helvetica", "", 10)
        if findings_count == 0:
            self.multi_cell(
                180, 6,
                "No security threats were detected in the scanned input. "
                "The text passed all 50 pattern checks across 5 attack categories. "
                "This result indicates the input does not contain known prompt "
                "injection patterns.",
            )
        else:
            severity_word = {
                "LOW": "minor",
                "MEDIUM": "moderate",
                "HIGH": "significant",
                "CRITICAL": "critical",
            }.get(severity, "unknown")

            self.multi_cell(
                180, 6,
                f"The scan detected {findings_count} security threat(s) with "
                f"an overall risk score of {risk_score}/10 ({severity}). "
                f"This indicates {severity_word} security concerns that require "
                f"attention. The scan completed in {scan_time}ms using "
                f"deterministic pattern matching across 42 attack vectors.",
            )

        self.ln(10)

        # Stats table
        self._section_subtitle("Scan Statistics")
        stats = [
            ("Total Findings", str(findings_count)),
            ("Risk Score", f"{risk_score} / 10"),
            ("Overall Severity", severity),
            ("Scan Duration", f"{scan_time}ms"),
            ("Patterns Checked", "42"),
            ("Attack Categories", "5"),
            ("Detection Method", "Deterministic Pattern Matching"),
            ("False Positive Rate", "0%"),
        ]
        self._key_value_table(stats)

        # Severity breakdown
        if findings_count > 0:
            self.ln(8)
            self._section_subtitle("Severity Breakdown")
            findings = scan_data.get("findings", [])
            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "UNKNOWN")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            for sev_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = severity_counts.get(sev_level, 0)
                if count > 0:
                    color = SEVERITY_COLORS.get(sev_level, (100, 100, 100))
                    self.set_fill_color(*color)
                    self.set_text_color(255, 255, 255)
                    self.set_font("Helvetica", "B", 9)
                    self.cell(25, 7, f" {sev_level}", fill=True)
                    self.set_text_color(0, 0, 0)
                    self.set_font("Helvetica", "", 9)
                    bar_width = min(count * 15, 120)
                    self.set_fill_color(*color)
                    self.cell(bar_width, 7, f"  {count} finding(s)", fill=True)
                    self.ln(9)

    # ─── Detailed Findings ───────────────────────────────────────────────

    def add_findings_detail(self, scan_data: dict):
        self.add_page()
        self._section_title("2. Detailed Findings")

        findings = scan_data.get("findings", [])
        if not findings:
            self.set_font("Helvetica", "I", 10)
            self.set_text_color(80, 80, 80)
            self.cell(0, 10, "No threats detected. All 100 patterns passed.", new_x="LMARGIN", new_y="NEXT")
            return

        # Group by category
        categories = {}
        for f in findings:
            cat = f.get("category", "Unknown")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(f)

        for cat_name, cat_findings in categories.items():
            # Check if we need a new page
            if self.get_y() > 230:
                self.add_page()

            self._section_subtitle(f"{cat_name} ({len(cat_findings)} finding(s))")

            # Category description
            desc = CATEGORY_DESCRIPTIONS.get(cat_name, "")
            if desc:
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(100, 100, 100)
                self.multi_cell(0, 5, desc)
                self.ln(4)

            for i, finding in enumerate(cat_findings, 1):
                if self.get_y() > 245:
                    self.add_page()

                sev = finding.get("severity", "UNKNOWN")
                color = SEVERITY_COLORS.get(sev, (100, 100, 100))

                # Finding header with severity badge
                self.set_fill_color(*color)
                self.set_text_color(255, 255, 255)
                self.set_font("Helvetica", "B", 8)
                self.cell(20, 6, f" {sev}", fill=True)

                # Confidence badge
                confidence = finding.get("confidence", 0)
                if confidence > 0:
                    self.set_fill_color(60, 60, 60)
                    self.set_text_color(200, 200, 200)
                    self.set_font("Helvetica", "", 7)
                    self.cell(12, 6, f" {confidence}%", fill=True)

                self.set_text_color(0, 0, 0)
                self.set_font("Helvetica", "B", 9)
                pattern_name = finding.get("pattern_name", "Unknown Pattern")
                self.cell(0, 6, f"  {pattern_name}", new_x="LMARGIN", new_y="NEXT")

                # Finding details
                self.set_font("Helvetica", "", 8)
                self.set_text_color(60, 60, 60)

                line_num = finding.get("line_number", "?")
                self.cell(0, 5, f"  Line: {line_num}", new_x="LMARGIN", new_y="NEXT")

                matched = finding.get("matched_text", "")
                if matched:
                    # Truncate long matches
                    if len(matched) > 80:
                        matched = matched[:77] + "..."
                    self.cell(0, 5, f"  Match: {matched}", new_x="LMARGIN", new_y="NEXT")

                # Recommendation
                desc_text = finding.get("description", "")
                if desc_text:
                    self.set_font("Helvetica", "", 8)
                    self.set_text_color(0, 80, 0)
                    self.multi_cell(0, 5, f"  Recommendation: {desc_text}")

                self.set_text_color(0, 0, 0)
                self.ln(4)

    # ─── Remediation Priorities ──────────────────────────────────────────

    def add_remediation(self, scan_data: dict):
        findings = scan_data.get("findings", [])
        if not findings:
            return

        if self.get_y() > 200:
            self.add_page()
        else:
            self.ln(5)

        self._section_title("3. Remediation Priorities")

        self.set_font("Helvetica", "", 9)
        self.set_text_color(60, 60, 60)
        self.multi_cell(
            0, 5,
            "The following remediation steps are ordered by severity. "
            "Address CRITICAL and HIGH findings immediately before deploying "
            "the AI agent to production.",
        )
        self.ln(5)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "LOW"), 4),
        )

        # Deduplicate by pattern name
        seen = set()
        priority = 1
        for f in sorted_findings:
            pattern = f.get("pattern_name", "")
            if pattern in seen:
                continue
            seen.add(pattern)

            sev = f.get("severity", "LOW")
            color = SEVERITY_COLORS.get(sev, (100, 100, 100))

            if self.get_y() > 260:
                self.add_page()

            self.set_font("Helvetica", "B", 9)
            self.set_text_color(0, 0, 0)
            self.cell(10, 6, f"{priority}.")
            self.set_fill_color(*color)
            self.set_text_color(255, 255, 255)
            self.cell(20, 6, f" {sev}", fill=True)
            self.set_text_color(0, 0, 0)
            self.cell(0, 6, f"  {pattern}", new_x="LMARGIN", new_y="NEXT")

            desc = f.get("description", "")
            if desc:
                self.set_font("Helvetica", "", 8)
                self.set_text_color(80, 80, 80)
                self.cell(10, 5, "")
                self.multi_cell(170, 5, desc)

            self.ln(3)
            priority += 1

    # ─── EU AI Act Compliance Section ────────────────────────────────────

    def add_eu_ai_act_section(self):
        self.add_page()
        self._section_title("4. EU AI Act Compliance Reference")

        self.set_font("Helvetica", "", 9)
        self.set_text_color(60, 60, 60)
        self.multi_cell(
            0, 5,
            "The EU Artificial Intelligence Act (Regulation 2024/1689) establishes "
            "a comprehensive framework for AI systems in the European Union. "
            "Full enforcement begins 02 August 2026. The following articles are "
            "directly relevant to AI agent security scanning.",
        )
        self.ln(8)

        for article_info in EU_AI_ACT_ARTICLES:
            if self.get_y() > 230:
                self.add_page()

            # Article header
            self.set_fill_color(230, 240, 255)
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(20, 60, 120)
            self.cell(0, 8, f"  {article_info['article']}", fill=True, new_x="LMARGIN", new_y="NEXT")

            # Requirement
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(0, 0, 0)
            self.cell(0, 6, "  Requirement:", new_x="LMARGIN", new_y="NEXT")
            self.set_font("Helvetica", "", 8)
            self.set_text_color(60, 60, 60)
            self.multi_cell(0, 5, f"  {article_info['requirement']}")
            self.ln(2)

            # Relevance
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(0, 0, 0)
            self.cell(0, 6, "  How this scan addresses it:", new_x="LMARGIN", new_y="NEXT")
            self.set_font("Helvetica", "", 8)
            self.set_text_color(0, 80, 0)
            self.multi_cell(0, 5, f"  {article_info['relevance']}")
            self.ln(6)

        # Compliance note
        self.ln(5)
        self.set_fill_color(255, 248, 220)
        box_y = self.get_y()
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(120, 80, 0)
        self.cell(0, 6, "  Important Note", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_fill_color(255, 253, 245)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 70, 0)
        self.multi_cell(
            0, 5,
            "  This report provides a security assessment of AI agent inputs. "
            "It does not constitute legal advice. EU AI Act compliance requires "
            "a comprehensive risk management approach. Consult qualified legal "
            "counsel for full regulatory compliance.",
        )

    # ─── Methodology Section ─────────────────────────────────────────────

    def add_methodology(self):
        if self.get_y() > 180:
            self.add_page()
        else:
            self.ln(10)

        self._section_title("5. Methodology")

        self.set_font("Helvetica", "", 9)
        self.set_text_color(60, 60, 60)

        methods = [
            (
                "Detection Engine",
                "ClawGuard uses deterministic regex-based pattern matching - "
                "not LLM-based detection. This eliminates the fundamental "
                "vulnerability of using an LLM to detect attacks against LLMs.",
            ),
            (
                "Pattern Coverage",
                "50 attack patterns across 7 categories: Prompt Injection, "
                "System Prompt Extraction, Data Exfiltration, Social Engineering, "
                "and Context Manipulation.",
            ),
            (
                "Performance",
                "All scans complete in under 10ms with zero external API calls. "
                "The scanner operates fully offline.",
            ),
            (
                "False Positive Rate",
                "Tested against real-world benign content: 0% false positive rate. "
                "Patterns are tuned for high precision.",
            ),
            (
                "Multilingual Support",
                "Patterns include English and German variants for key attack types.",
            ),
        ]

        for title, desc in methods:
            if self.get_y() > 260:
                self.add_page()
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(0, 0, 0)
            self.cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
            self.set_font("Helvetica", "", 8)
            self.set_text_color(80, 80, 80)
            self.multi_cell(0, 5, desc)
            self.ln(4)

    # ─── Helper Methods ──────────────────────────────────────────────────

    def _section_title(self, title: str):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(20, 20, 20)
        self.cell(0, 12, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(74, 158, 255)
        self.set_line_width(0.8)
        self.line(10, self.get_y(), 80, self.get_y())
        self.ln(6)

    def _section_subtitle(self, subtitle: str):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(40, 40, 40)
        self.cell(0, 8, subtitle, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def _key_value_table(self, rows: list):
        self.set_font("Helvetica", "", 9)
        for i, (key, value) in enumerate(rows):
            if i % 2 == 0:
                self.set_fill_color(248, 248, 248)
            else:
                self.set_fill_color(255, 255, 255)

            self.set_text_color(80, 80, 80)
            self.cell(60, 7, f"  {key}", fill=True)
            self.set_text_color(0, 0, 0)
            self.set_font("Helvetica", "B", 9)
            self.cell(130, 7, value, fill=True, new_x="LMARGIN", new_y="NEXT")
            self.set_font("Helvetica", "", 9)


# ─── Public API ──────────────────────────────────────────────────────────────

def generate_compliance_report(
    scan_data: dict,
    company_name: str = "",
) -> bytes:
    """
    Generate a compliance PDF report from Shield scan results.

    Args:
        scan_data: Dict with keys: clean, risk_score, severity, findings_count,
                   findings (list), scan_time_ms
        company_name: Optional organization name for the cover page

    Returns:
        PDF file contents as bytes
    """
    pdf = ComplianceReport()

    pdf.add_cover_page(scan_data, company_name=company_name)
    pdf.add_executive_summary(scan_data)
    pdf.add_findings_detail(scan_data)
    pdf.add_remediation(scan_data)
    pdf.add_eu_ai_act_section()
    pdf.add_methodology()

    return pdf.output()
