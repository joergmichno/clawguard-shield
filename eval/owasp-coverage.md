# ClawGuard v0.3.0 — OWASP Top 10 for LLM Applications (2025) Coverage Map

**Datum:** 2026-03-17
**Scanner:** clawguard.py v0.3.0 (38 Regex-Patterns, 5 Kategorien)
**Methode:** Manuelle Zuordnung jedes Patterns zu OWASP-Kategorien

## Coverage-Matrix

| OWASP ID | Name | Abdeckung | Relevante Patterns | Machbar per Regex? |
|----------|------|-----------|--------------------|--------------------|
| LLM01 | Prompt Injection | **STARK** (14 Patterns) | Direct Override EN/DE, Synonym Override EN/DE, New Instructions Override, System Prompt Extraction, Role-Play Escape, Delimiter Injection, Encoded Bypass, Token Smuggling, Indirect Instruction Reset, Forget/Reset Override, Indirect Prompt Extraction + Leet/Space-Evasion Preprocessor | **JA** — Kernkompetenz des Scanners. Regex ist ideales Werkzeug fuer bekannte Injection-Muster. Limitation: Semantische Injections (kontextabhaengig, keine Keywords) werden nicht erkannt. |
| LLM02 | Insecure Output Handling | **TEILWEISE** (6 Patterns) | Data Exfiltration Patterns: API Key Leak, Private Key Material, Password Cleartext, DB Connection String, Webhook Exfiltration, Email Harvesting | **TEILWEISE** — Scanner erkennt Secrets/Credentials im Output. Aber: XSS, SQL Injection, SSRF im generierten Output (z.B. LLM gibt `<script>` zurueck) wird NICHT geprueft. Regex koennte HTML/JS-Injection-Patterns im Output erkennen, ist aber nicht implementiert. |
| LLM03 | Training Data Poisoning | **KEINE** | — | **NEIN** — Betrifft den Trainingsprozess, nicht den Runtime-Input. Erkennung erfordert statistische Analyse der Trainingsdaten, Data Provenance, Anomaly Detection. Voellig ausserhalb des Regex-Scope. |
| LLM04 | Model Denial of Service | **KEINE** | — | **TEILWEISE** — Einige Muster sind per Regex erkennbar: extrem lange Inputs, Wiederholungsschleifen ("repeat this 10000 times"), rekursive Task-Expansion. Aktuell nicht implementiert. Input-Laenge-Check waere trivial ergaenzbar. |
| LLM05 | Supply Chain Vulnerabilities | **MINIMAL** (1 Pattern) | Package/Dependency Install (pip/npm/apt install) | **TEILWEISE** — Pattern erkennt Install-Commands, aber NICHT: manipulierte Modelle, kompromittierte Plugins, Typosquatting-Packages (z.B. `pip install reqeusts`). Typosquatting-Regex gegen bekannte Package-Listen waere moeglich aber wartungsintensiv. |
| LLM06 | Sensitive Information Disclosure | **GUT** (8 Patterns) | System Prompt Extraction, Indirect Prompt Extraction + API Key Leak, Private Key Material, Password Cleartext, DB Connection String, Email Harvesting, Webhook Exfiltration | **JA** — Regex erkennt Extraction-Versuche (Input-Seite) UND Credential-Leaks (Output-Seite). Luecke: PII-Detection (Namen, Adressen, Telefonnummern, IBAN) fehlt. PII-Regex ist machbar und gaengig. |
| LLM07 | Insecure Plugin Design | **INDIREKT** (15 Patterns) | Dangerous Command Patterns (5) + Python Obfuscation Patterns (10) — erkennen gefaehrliche Aktionen die ein unsicheres Plugin ausfuehren koennte | **TEILWEISE** — Scanner erkennt die AUSWIRKUNGEN unsicherer Plugins (Code Execution, File Access, Shell Commands), aber NICHT das architektonische Problem (fehlende Input-Validierung, ueberprivilegierte Plugins). Architektur-Audit ist nicht per Regex loesbar. |
| LLM08 | Excessive Agency | **MINIMAL** (3 Patterns) | Social Engineering: Urgency Manipulation, Authority Impersonation, Confidentiality Trap — erkennen Manipulation die zu unkontrollierten Aktionen fuehrt | **TEILWEISE** — Patterns erkennen Manipulationsversuche, aber NICHT ob ein Agent zu viele Berechtigungen hat oder autonome Aktionen ohne Approval ausfuehrt. Ergaenzbar: Patterns fuer "execute without asking", "don't confirm", "auto-approve", "skip verification". |
| LLM09 | Overreliance | **KEINE** | — | **NEIN** — Betrifft menschliches Verhalten (blindes Vertrauen in LLM-Output). Keine technische Input/Output-Eigenschaft die per Regex erkennbar waere. Erfordert Prozess-Design (Human-in-the-Loop), nicht Scanning. |
| LLM10 | Model Theft | **KEINE** | — | **TEILWEISE** — Einige Angriffsvektoren sind per Regex erkennbar: Model-Weight-Extraction-Prompts ("export your weights", "serialize your model"), excessive API-Probing-Patterns. Aber: Side-Channel-Attacks, API-Rate-Abuse, physischer Zugriff sind nicht per Text-Scan erkennbar. |

## Zusammenfassung

| Status | Anzahl | OWASP IDs |
|--------|--------|-----------|
| Starke Abdeckung | 2 | LLM01 (Prompt Injection), LLM06 (Sensitive Info Disclosure) |
| Teilweise Abdeckung | 3 | LLM02 (Insecure Output), LLM05 (Supply Chain), LLM07 (Insecure Plugin), LLM08 (Excessive Agency) |
| Keine Abdeckung | 4 | LLM03 (Training Data Poisoning), LLM04 (Model DoS), LLM09 (Overreliance), LLM10 (Model Theft) |

**Coverage Score: 2/10 stark, 4/10 teilweise, 4/10 keine = ~35% effektive Abdeckung**

## Umsetzbare Luecken (Regex-machbar, nach Impact sortiert)

1. **LLM04 — Model DoS:** Input-Laenge-Limit + Wiederholungspatterns (`repeat .* \d{3,} times`, extrem lange Zeilen). Aufwand: ~1h.
2. **LLM06 — PII-Detection:** Deutsche IBAN, Telefonnummern, Steuernummern, E-Mail-Adressen im Output. Aufwand: ~2h.
3. **LLM08 — Excessive Agency:** Patterns fuer "don't ask/confirm", "auto-execute", "skip approval", "ohne Rueckfrage". Aufwand: ~1h.
4. **LLM02 — Output Injection:** HTML/JS-Injection (`<script>`, `javascript:`, `onerror=`), SQL-Fragments im LLM-Output. Aufwand: ~2h.
5. **LLM10 — Model Theft:** Extraction-Prompts fuer Weights/Architecture ("export model", "your architecture is"). Aufwand: ~1h.

## Nicht per Regex loesbar

- **LLM03 (Training Data Poisoning):** Erfordert Data Provenance + Anomaly Detection auf Trainingsebene.
- **LLM09 (Overreliance):** Menschliches/organisatorisches Problem, kein technisches Signal im Text.
- **LLM05 (Supply Chain, tiefere Ebene):** Package-Integrity-Checks, SBOM-Analyse, Signatur-Validierung — ausserhalb Regex-Scope.
- **LLM07 (Plugin-Architektur):** Least-Privilege-Design, Sandboxing — erfordert Code-Audit, nicht Text-Scanning.
