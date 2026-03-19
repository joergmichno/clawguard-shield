# ClawGuard v0.5.8 — OWASP Top 10 for Agentic Applications 2026 Coverage

**Datum:** 2026-03-18 | **Patterns:** 103 | **Sprachen:** 9

## Coverage-Matrix

| ID | Name | Coverage | Relevante Patterns | Per Regex? |
|----|------|----------|-------------------|------------|
| ASI01 | Agent Goal Hijack | **GUT** | Direct Override, Synonym Override, Agent Goal Hijack, Broad Ignore, Instruction Header Injection | Teilweise |
| ASI02 | Tool Misuse & Exploitation | **STARK** | Dangerous Commands (8), Shell Injection, Sudo, Package Install | Ja |
| ASI03 | Identity & Privilege Abuse | **MINIMAL** | Authority Impersonation, Agent Impersonation | Nein (Laufzeit) |
| ASI04 | Agentic Supply Chain | **KEINE** | — | Nein (Architektur) |
| ASI05 | Unexpected Code Execution | **STARK** | Code Obfuscation (12), Eval/Exec, Base64 Decode, String Assembly | Ja |
| ASI06 | Memory & Context Poisoning | **GUT** | Memory/Persistence Injection, Forget/Reset, Indirect Instruction Reset | Teilweise |
| ASI07 | Insecure Inter-Agent Comm | **MINIMAL** | Agent Impersonation | Nein (Netzwerk) |
| ASI08 | Cascading Failures | **KEINE** | — | Nein (Architektur) |
| ASI09 | Human-Agent Trust Exploit | **GUT** | Social Engineering (5), Verification Bypass, Urgency Manipulation, Approval Bypass | Teilweise |
| ASI10 | Rogue Agents | **KEINE** | — | Nein (Monitoring) |

## Zusammenfassung

| Status | Count | IDs |
|--------|-------|-----|
| Starke Abdeckung | 2 | ASI02, ASI05 |
| Gute Abdeckung | 3 | ASI01, ASI06, ASI09 |
| Minimale Abdeckung | 2 | ASI03, ASI07 |
| Keine Abdeckung | 3 | ASI04, ASI08, ASI10 |

**Effektive Coverage: ~50% (5/10 substantiell abgedeckt)**

## Nicht per Regex loesbar (ASI04, ASI08, ASI10)
Diese Kategorien erfordern Laufzeit-Monitoring, Architektur-Reviews oder Policy-Enforcement — klassische Compliance-Beratung, nicht Input-Scanning.
