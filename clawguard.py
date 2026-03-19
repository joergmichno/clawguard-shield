#!/usr/bin/env python3
"""
ClawGuard v0.5.0 – The Firewall for Autonomous AI Agents.
A CLI tool that scans text for prompt injections, dangerous commands,
and social engineering patterns.

Usage:
    python3 clawguard.py <file>          Scan a text file
    python3 clawguard.py --stdin         Scan from standard input
    echo "text" | python3 clawguard.py   Pipe text directly

Exit Codes:
    0 = Clean (no threats found)
    1 = Threats detected
    2 = Error (file not found, etc.)

(c) 2026 Jörg Michno
"""

import re
import sys
import json
import argparse
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List
from datetime import datetime, timezone


# ─── Severity Levels ─────────────────────────────────────────────────────────

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def score(self) -> int:
        return {"LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}[self.value]


# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: Severity
    category: str
    pattern_name: str
    matched_text: str
    line_number: int
    context: str
    recommendation: str
    confidence: int = 0


@dataclass
class ScanReport:
    timestamp: str
    source: str
    total_lines: int
    total_findings: int = 0
    risk_score: int = 0
    risk_level: str = "CLEAN"
    findings: List[Finding] = field(default_factory=list)


# ─── Pattern Database ─────────────────────────────────────────────────────────
# Each pattern: (name, regex, severity, category, recommendation)

PROMPT_INJECTION_PATTERNS = [
    # --- Direct Instruction Override (EN + DE) ---
    (
        "Direct Override (EN)",
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|guidelines?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK this input immediately. This is a classic prompt injection attempting to override the agent's system instructions.",
    ),
    (
        "Direct Override (DE)",
        r"(?i)ignoriere?\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?)\s+(Anweisung(?:en)?|Regeln?|Instruktion(?:en)?|Befehle?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN. Klassische Prompt-Injection die versucht, die Systemanweisungen zu überschreiben.",
    ),
    (
        "New Instructions Override",
        r"(?i)(you\s+are\s+now|ab\s+jetzt\s+bist\s+du|from\s+now\s+on\s+you\s+are|your\s+new\s+(role|instructions?|task)\s+(is|are))",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK. Attempt to redefine the agent's identity or role mid-conversation.",
    ),
    (
        "System Prompt Extraction",
        r"(?i)(show|reveal|print|display|output|repeat|give\s+me|zeig|nenne|wiederhole)\s+(.{0,40}?)(system\s*prompt|initial\s*prompt|hidden\s*prompt|Systemprompt|internal\s+instructions?|original\s+instructions?|geheime?n?\s+Anweisung(?:en)?|interne?n?\s+Anweisung(?:en)?|deine?n?\s+Anweisung(?:en)?)",
        Severity.HIGH,
        "Prompt Injection",
        "This input attempts to extract the agent's system prompt. Sensitive internal instructions could be leaked.",
    ),
    (
        "Role-Play Escape",
        r"(?i)(pretend|act\s+as\s+if|imagine|tu\s+so\s+als|stell\s+dir\s+vor).{0,50}(no\s+rules?|no\s+restrictions?|keine\s+Regeln?|without\s+limits?|ohne\s+Einschränkungen?)",
        Severity.HIGH,
        "Prompt Injection",
        "Jailbreak attempt via role-play scenario to bypass safety constraints.",
    ),
    (
        "Delimiter Injection",
        r"(```system|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>|<\|system\|>|<\|user\|>|<\|assistant\|>)",
        Severity.CRITICAL,
        "Prompt Injection",
        "CRITICAL: Injection of model-specific delimiters to manipulate the conversation structure. This is a sophisticated attack.",
    ),
    (
        "Encoded Bypass (Base64 hint)",
        r"(?i)(decode|base64|atob|eval)\s*\(.{0,100}\)",
        Severity.HIGH,
        "Prompt Injection",
        "Possible attempt to smuggle encoded payloads past text filters.",
    ),
    (
        "Token Smuggling",
        r"(?i)(ignore|bypass|skip|disable)\s+(safety|filter|guard|moderation|content\s*policy|Sicherheit|Schutz)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to explicitly disable or bypass security filters.",
    ),
    # --- v0.2.0: Synonym Bypass Defense ---
    (
        "Synonym Override (EN)",
        r"(?i)(disregard|forget|dismiss|override|overrule|nullify|void|abandon|drop|suppress|set\s+aside|throw\s+out)\s+(all\s+|any\s+)?(previous|prior|above|earlier|preceding|antecedent|foregoing|existing|current|original|below|further|any)?\s*(instructions?|rules?|prompts?|guidelines?|directives?|regulations?|constraints?|policies?|orders?|commands?|directions?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK: Synonym-based prompt injection detected. Uses alternative vocabulary to bypass basic keyword filters.",
    ),
    (
        "Synonym Override (DE)",
        r"(?i)(vergiss|verwirf|übergehe?|überschreibe?|missachte|setze?\s+außer\s+Kraft|hebe?\s+auf)\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?|bestehenden?|aktuellen?|ursprünglichen?)?\s*(Anweisung(?:en)?|Regeln?|Instruktion(?:en)?|Befehle?|Richtlinien?|Vorgaben?|Vorschriften?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Synonym-basierte Prompt-Injection auf Deutsch erkannt.",
    ),
    (
        "Indirect Instruction Reset",
        r"(?i)(start\s+(fresh|over|anew|from\s+scratch)\s+.{0,20}(instruction|context|prompt|conversation|session|memory|rule)|begin\s+a\s+new\s+(session|context|conversation)|reset\s+(your|all)\s+(memory|context|instructions?)|fang\s+(neu|von\s+vorne)\s+an\s+.{0,20}(Anweisung(?:en)?|Kontext|Regeln?|Sitzung))",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to reset the agent's instruction context via indirect phrasing.",
    ),
    # --- v0.4.0: Adversarial Evasion Defense ---
    (
        "Forget/Reset Override",
        r"(?i)(forg[eo]t\s+(everything|all|it\s+all|your\s+prompt|about\s+the|the\s+previous|what\s+you|wah?t)|new\s+session|wipe\s+(your\s+)?memory|vergiss\s+alles|oublie\s+tout)",
        Severity.HIGH,
        "Prompt Injection",
        "Context wipe attempt using 'forget everything' or 'new session' phrasing.",
    ),
    (
        "Indirect Prompt Extraction",
        r"(?i)(disclose|leak|expose|divulge|dump|gimme|give\s+me|tell\s+me|repeat|duplicate|list)\s+.{0,30}(instructions?|prompt|config|rules?|settings?|parameters?|password)",
        Severity.HIGH,
        "Prompt Injection",
        "Indirect attempt to extract system prompt using synonyms like disclose/leak/expose.",
    ),
    # --- v0.5.1: German Override Variants ---
    (
        "German Override Variants",
        r"(?i)(h[oö]re?\s+nicht\s+auf|vergiss\s+alles\s+(davor|zuvor|was)|ignoriere?\s+(und|alles)|fang\s+neu\s+an|ab\s+jetzt\s+ignorier)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Deutsche Variante einer Instruction-Override-Injection.",
    ),
    (
        "Print/Spellcheck Prompt Extraction",
        r"(?i)(print|spell\s*check|proofread|korrigiere?|drucke?n?\s+Sie|gib\s+aus|ausgeben)\s+.{0,30}(above|obige[nr]?|text|prompt|input|eingabe|aufforderung)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to extract system prompt via print/spellcheck request.",
    ),
    # --- v0.5.1: French (FR) Patterns ---
    (
        "Direct Override (FR)",
        r"(?i)(ignore[sz]?|ignorer|ignorons)\s+(toutes?\s+)?(les\s+)?(instructions?|consignes?|r[eéèê]gles?|directives?)(\s+pr[eéèê]c[eéèê]dentes?|\s+ant[eéèê]rieures?)?",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Franzoesische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (FR)",
        r"(?i)([aà]\s+partir\s+de\s+maintenant\s+tu\s+es|d[eéèê]sormais\s+tu\s+es|tu\s+es\s+maintenant|tes?\s+nouvelles?\s+instructions?\s+(sont|est))",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Franzoesische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (FR)",
        r"(?i)(montre|r[eéèê]v[eéèê]le|affiche|donne|divulgue|d[eéèê]voile)[sz]?\s*[- ]?(moi\s+)?(tes?\s+|les?\s+)?(instructions?\s+secr[eéèê]tes?|consignes?\s+secr[eéèê]tes?|instructions?\s+cach[eéèê]es?|prompt\s+syst[eéèê]me|instructions?\s+internes?|consignes?\s+initiales?|instructions?\s+originales?)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Franzoesische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (FR)",
        r"(?i)(je\s+suis\s+(ton|votre|l[e'])\s*(administrateur|admin|cr[eéèê]ateur|responsable|propri[eéèê]taire|sup[eéèê]rieur|chef|patron))",
        Severity.HIGH,
        "Social Engineering",
        "BLOCKIEREN: Franzoesische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (FR)",
        r"(?i)(oublie[sz]?\s+(tout(es?\s+les?\s+instructions?)?|tes?\s+consignes?|ce\s+qu|ta\s+m[eéèê]moire)|efface[sz]?\s+(ta\s+m[eéèê]moire|tes?\s+instructions?|tout)|r[eéèê]initialise[sz]?\s+(ta\s+m[eéèê]moire|tes?\s+instructions?|tout))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Franzoesische Prompt-Injection erkannt.",
    ),
    (
        "Role-Play Escape (FR)",
        r"(?i)(fais\s+comme\s+si|imagine\s+que|pr[eéèê]tends?\s+que|comporte[sz]?\s*[- ]?toi\s+comme).{0,50}(sans\s+r[eéèê]gles?|sans\s+restrictions?|sans\s+limites?|aucune\s+restriction)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Franzoesische Prompt-Injection erkannt.",
    ),
    # --- v0.5.1: Spanish (ES) Patterns ---
    (
        "Direct Override (ES)",
        r"(?i)(ignor[ae]r?|ignoren?|ignore)\s+(todas?\s+)?(las\s+)?(instrucciones?\s+(previas?|anteriores?)|reglas?\s+(previas?|anteriores?)|directivas?\s+(previas?|anteriores?)|indicaciones?\s+(previas?|anteriores?))",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Spanische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (ES)",
        r"(?i)(a\s+partir\s+de\s+ahora\s+(eres|sos|act[uú]a)|desde\s+ahora\s+(eres|sos|act[uú]a)|tus?\s+nuevas?\s+instrucciones?\s+(son|es)|ahora\s+eres)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Spanische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (ES)",
        r"(?i)(mu[eé]strame|revela|ense[nñ]ame|dime|divulga|muestra)\s*.{0,30}?(instrucciones?\s+secretas?|instrucciones?\s+internas?|instrucciones?\s+ocultas?|prompt\s+del?\s+sistema|instrucciones?\s+originales?|configuraci[oó]n\s+interna)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Spanische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (ES)",
        r"(?i)(soy\s+(tu|el|su)\s*(administrador|admin|creador|responsable|propietario|superior|jefe|due[nñ]o))",
        Severity.HIGH,
        "Social Engineering",
        "BLOCKIEREN: Spanische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (ES)",
        r"(?i)(olvid[aeo](r|te|n)?\s+(todo|todas?\s+las?\s+instrucciones?|tus?\s+reglas?|lo\s+anterior|que\s+dije)|borra(r)?\s+(tu\s+memoria|todas?\s+las?\s+instrucciones?|todo)|reinicia(r)?\s+(tu\s+memoria|tus?\s+instrucciones?|todo))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Spanische Prompt-Injection erkannt.",
    ),
    # --- v0.5.1: Italian (IT) Patterns ---
    (
        "Direct Override (IT)",
        r"(?i)(ignor[ai](?:te|re|no)?|ignori)\s+(tutte?\s+)?(le\s+)?(istruzioni\s+precedenti|istruzioni\s+anteriori|regole\s+precedenti|direttive\s+precedenti|indicazioni\s+precedenti)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Italienische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (IT)",
        r"(?i)(da\s+adesso\s+(sei|sarai|diventi|agisci)|d[']ora\s+in\s+poi\s+(sei|sarai|diventi|agisci)|adesso\s+sei|le\s+tue\s+nuove\s+istruzioni\s+(sono|saranno))",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Italienische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (IT)",
        r"(?i)(mostr[ai](?:mi|temi)?|rivel[ai](?:mi)?|dimmi|divulga|esponi|stampa)\s*.{0,30}?(istruzioni\s+segrete|istruzioni\s+interne|istruzioni\s+nascoste|istruzioni\s+originali|prompt\s+di\s+sistema|configurazione\s+interna)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Italienische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (IT)",
        r"(?i)(sono\s+(il\s+tuo|il|la\s+tua)\s*(amministratore|admin|creatore|responsabile|proprietario|superiore|capo))",
        Severity.HIGH,
        "Social Engineering",
        "BLOCKIEREN: Italienische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (IT)",
        r"(?i)(dimentica(re?)?\s+(tutto|tutte?\s+le\s+istruzioni|le\s+tue\s+regole|quanto\s+detto)|cancella(re?)?\s+(la\s+tua\s+memoria|tutte?\s+le\s+istruzioni|tutto)|reimposta(re?)?\s+(la\s+tua\s+memoria|le\s+tue\s+istruzioni|tutto)|azzera(re?)?\s+(la\s+tua\s+memoria|tutto))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Italienische Prompt-Injection erkannt.",
    ),
    # --- v0.5.1: Dutch (NL) Patterns ---
    (
        "Direct Override (NL)",
        r"(?i)(negeer|negeert|negeren|sla\s+over)\s+(alle?\s+)?(vorige|eerdere|bovenstaande|voorgaande|voorafgaande)\s+(instructies?|regels?|opdrachten?|richtlijnen?|aanwijzingen?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Niederlaendische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (NL)",
        r"(?i)(vanaf\s+nu\s+ben\s+je|je\s+bent\s+nu|vanaf\s+nu\s+is\s+je\s+rol|je\s+nieuwe\s+instructies?\s+(zijn|is)|doe\s+alsof\s+je\s+nu\s+een)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Niederlaendische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (NL)",
        r"(?i)(toon|laat\s+zien|geef|onthul|vertel)\s*.{0,30}?(geheime?\s+instructies?|verborgen\s+instructies?|systeem\s*prompt|interne?\s+instructies?|oorspronkelijke?\s+instructies?|geheime?\s+opdrachten?)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Niederlaendische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (NL)",
        r"(?i)(ik\s+ben\s+(je|jouw|de)\s*(beheerder|admin(?:istrator)?|eigenaar|maker|baas|leidinggevende|superieur))",
        Severity.HIGH,
        "Social Engineering",
        "BLOCKIEREN: Niederlaendische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (NL)",
        r"(?i)(vergeet\s+(alles|al\s+je\s+instructies?|je\s+regels?|wat\s+je|het\s+vorige)|wis\s+(je\s+geheugen|alles|alle\s+instructies?)|begin\s+opnieuw|reset\s+je\s+(geheugen|instructies?))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Niederlaendische Prompt-Injection erkannt.",
    ),
    # --- v0.5.1: Polish (PL) Patterns ---
    (
        "Direct Override (PL)",
        r"(?i)([zź]ignoruj|ignoruj|ignorowa[cć])\s+(wszystkie\s+)?(poprzednie|wcze[sś]niejsze|dotychczasowe|powy[zż]sze)\s+(instrukcje|polecenia|zasady|wytyczne|regu[lł]y|komendy)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Polnische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (PL)",
        r"(?i)(od\s+teraz\s+jeste[sś]|teraz\s+jeste[sś]|od\s+tej\s+pory\s+jeste[sś]|twoje\s+nowe\s+(instrukcje|polecenia|zasady)\s+(to|s[aą])|zachowuj\s+si[eę]\s+jak)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Polnische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (PL)",
        r"(?i)(poka[zż]|ujawnij|wy[sś]wietl|zdrad[zź]|wyjaw|powiedz)\s*.{0,30}?(tajne\s+instrukcje|ukryte\s+instrukcje|sw[oó]j\s+prompt|prompt\s+systemowy|wewn[eę]trzne\s+instrukcje|instrukcje\s+systemowe|pocz[aą]tkowe\s+instrukcje)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Polnische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (PL)",
        r"(?i)(jestem\s+(twoim|tw[oó]j)\s*(administratorem|adminem|tw[oó]rc[aą]|w[lł]a[sś]cicielem|prze[lł]o[zż]onym|szefem|zarz[aą]dc[aą]))",
        Severity.HIGH,
        "Social Engineering",
        "BLOCKIEREN: Polnische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (PL)",
        r"(?i)(zapomnij\s+(wszystko|o\s+wszystkim|poprzednie|swoje\s+instrukcje)|wyczy[sś][cć]\s+(pami[eę][cć]|swoje\s+instrukcje|wszystko)|zacznij\s+od\s+nowa|wyma[zż]\s+(pami[eę][cć]|wszystko)|zresetuj\s+(pami[eę][cć]|instrukcje|wszystko))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Polnische Prompt-Injection erkannt.",
    ),
    # --- v0.5.1: Portuguese (PT) Patterns ---
    (
        "Direct Override (PT)",
        r"(?i)(ignor[ea]r?|ignor[ea])\s+(todas?\s+)?(as\s+)?(instru[cç][oõ]es|regras|diretrizes|orienta[cç][oõ]es|comandos)\s+(anteriores|pr[eé]vias|acima|passadas)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Portugiesische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (PT)",
        r"(?i)(a\s+partir\s+de\s+agora\s+voc[eê]\s+[eé]|agora\s+voc[eê]\s+[eé]|de\s+agora\s+em\s+diante\s+voc[eê]|suas?\s+novas?\s+(instru[cç][oõ]es|regras|diretrizes)\s+(s[aã]o|[eé])|comporte-?\s*se\s+como|a\s+partir\s+de\s+agora\s+tu\s+[eé]s|agora\s+tu\s+[eé]s)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Portugiesische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (PT)",
        r"(?i)(mostre|revele|exiba|divulgue|mostra|apresente|diga)\s*.{0,30}?(instru[cç][oõ]es\s+secretas|instru[cç][oõ]es\s+ocultas|seu\s+prompt|prompt\s+do\s+sistema|instru[cç][oõ]es\s+internas|instru[cç][oõ]es\s+iniciais|configura[cç][aã]o\s+interna|prompt\s+original)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Portugiesische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (PT)",
        r"(?i)(eu\s+sou\s+(seu|teu|o)\s*(administrador|admin|criador|dono|propriet[aá]rio|respons[aá]vel|chefe|gerente|desenvolvedor))",
        Severity.HIGH,
        "Social Engineering",
        "BLOCKIEREN: Portugiesische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (PT)",
        r"(?i)(esque[cç]a\s+(tudo|todas?\s+(as\s+)?(instru[cç][oõ]es|regras))|apague\s+(sua\s+)?mem[oó]ria|apague\s+tudo|recomece|limpe\s+(sua\s+)?mem[oó]ria|reset[ea]r?\s+(sua\s+)?mem[oó]ria|comece\s+do\s+zero|comece\s+de\s+novo)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Portugiesische Prompt-Injection erkannt.",
    ),
    # --- v0.5.1: Turkish (TR) Patterns ---
    (
        "Direct Override (TR)",
        r"(?i)([oö]nceki\s+(t[uü]m\s+)?|t[uü]m\s+([oö]nceki\s+)?)(talimatlar[iı]|kurallar[iı]|y[oö]nergeleri|emirleri)\s*.{0,20}?(yok\s+say|g[oö]rmezden\s+gel|ihmal\s+et|dikkate\s+alma|unut|gec)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Tuerkische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (TR)",
        r"(?i)([sş]imdi\s+sen\s+(bir\s+)?|bundan\s+sonra\s+sen|art[iı]k\s+sen|yeni\s+talimatlar[iı]n\s+|yeni\s+kurallar[iı]n\s+|kendini\s+.{0,30}?\s+gibi\s+davran|sen\s+art[iı]k\s+bir\s+)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Tuerkische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (TR)",
        r"(?i)(g[oö]ster|a[cç][iı]kla|payla[sş]|s[oö]yle|ver|yaz)\s*.{0,30}?(gizli\s+talimatlar|sistem\s+prompt|[iı][cç]\s+talimatlar|ba[sş]lang[iı][cç]\s+talimatlar|gizli\s+kurallar|gizli\s+y[oö]nergeler|dahili\s+yap[iı]land[iı]rma|orijinal\s+prompt)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Tuerkische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (TR)",
        r"(?i)(ben\s+senin\s+(y[oö]neticin|admin|yarat[iı]c[iı]n|sahibin|geli[sş]tiricin|patronun|amiriniz|m[uü]d[uü]r[uü]n)\s*(i|[iı]m|iy[iı]m|[iı]y[iı]m)?|ben\s+admin[iı]m|ben\s+y[oö]neticiyim)",
        Severity.HIGH,
        "Social Engineering",
        "BLOCKIEREN: Tuerkische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (TR)",
        r"(?i)(her\s+[sş]eyi\s+unut|haf[iı]zan[iı]\s+sil|ba[sş]tan\s+ba[sş]la|t[uü]m\s+(haf[iı]zan[iı]|belle[gğ]ini)\s+sil|kendini\s+s[iı]f[iı]rla|fabrika\s+ayarlar[iı]na\s+d[oö]n|s[iı]f[iı]rla|reset[le]*)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Tuerkische Prompt-Injection erkannt.",
    ),
    # --- v0.5.9: Japanese (JA) Patterns ---
    (
        "Direct Override (JA)",
        r"(以前の|前の|これまでの|先ほどの|全ての|すべての).{0,10}?(指示|命令|ルール|プロンプト|ガイドライン|制約).{0,10}?(無視|忘れ|取り消|破棄|捨て|従わな|聞かな)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Japanische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (JA)",
        r"(今から(あなた|お前|君)は|新しい(指示|命令|ルール)に従|これからは.{0,15}?として(振る舞|行動|動作|機能)|(あなた|お前|君)の(新しい|本当の)(役割|目的|任務|使命)は)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Japanische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (JA)",
        r"(システムプロンプト|秘密の指示|隠された(指示|ルール|命令)|内部(設定|構成|指示)|初期(プロンプト|指示|設定)).{0,15}?(見せ|教え|表示|出力|共有|開示|公開|書い)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Japanische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (JA)",
        r"(私は(あなたの)?(管理者|開発者|作成者|オーナー|所有者|アドミン|上司|責任者)(です|だ|である|だよ|ですよ)|私が(管理者|開発者|アドミン)(です|だ))",
        Severity.HIGH,
        "Social Engineering",
        "BLOCKIEREN: Japanische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (JA)",
        r"(全て忘れ|すべて忘れ|メモリ.{0,5}?(消去|削除|クリア|リセット)|リセットして|最初から(やり直|始め)|初期(状態|設定)に(戻|リセット)|記憶を(消|削除|リセット))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Japanische Prompt-Injection erkannt.",
    ),
    # --- v0.5.9: Korean (KO) Patterns ---
    (
        "Direct Override (KO)",
        r"(이전\s*(지시|명령|지침|규칙)[을를]?\s*(무시|잊어|취소|삭제)|(?:모든|전부|모두)\s*(지시|명령|지침)[을를]?\s*(무시|잊어|취소)|이전에\s*받은\s*(지시|명령)[을를]?\s*무시)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Koreanische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (KO)",
        r"(지금부터\s*너는|지금부터\s*당신은|새로운\s*(지시|명령|역할)[을를]?\s*(따라|따르|수행)|이제부터\s*(너는|당신은|새로운))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Koreanische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (KO)",
        r"(시스템\s*프롬프트[를을]?\s*(보여|알려|출력|공개)|비밀\s*(지시|명령|프롬프트)[를을]?\s*(보여|알려|출력|공개)|숨겨진\s*(지시|명령|규칙)[를을]?\s*(보여|알려|공개))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Koreanische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (KO)",
        r"(나는\s*(너의|당신의)?\s*(관리자|개발자|운영자|제작자|소유자|루트|어드민)(이야|입니다|이에요|야)|내가\s*(관리자|개발자|운영자)(이니까|이므로|라서))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Koreanische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (KO)",
        r"(모두\s*잊어|전부\s*잊어|초기화\s*(해|하세요|하십시오)|처음부터\s*다시\s*시작|메모리[를을]?\s*(삭제|초기화|리셋|클리어)|기억[을를]?\s*(지워|삭제|리셋|초기화))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Koreanische Prompt-Injection erkannt.",
    ),
    # --- v0.5.9: Chinese Mandarin (ZH) Patterns ---
    (
        "Direct Override (ZH)",
        r"(忽略之前的(指令|指示|命令|规则)|无视(之前|以前|前面|所有)(的)?(指令|指示|命令|规则|提示)|忽略(所有|全部|一切)(之前的|以前的)?(指令|指示|命令|规则))",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Chinesische Prompt-Injection erkannt.",
    ),
    (
        "New Instructions (ZH)",
        r"(从现在开始你是|你现在的角色是|你的新角色是|你现在是一个|从现在起你是|接下来你(将|要|会)扮演|新的指令[是为]|请遵循新的(指令|指示|命令))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Chinesische Prompt-Injection erkannt.",
    ),
    (
        "System Prompt Extraction (ZH)",
        r"(显示你的系统提示|告诉我你的秘密指令|展示(你的)?(系统|隐藏)(提示|指令|规则|消息)|泄露(你的)?(系统|初始|原始)(提示|指令|设定|设置)|输出(你的)?(系统|隐藏)(提示|指令|消息))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Chinesische Prompt-Injection erkannt.",
    ),
    (
        "Authority Claim (ZH)",
        r"(我是(你的)?(管理员|开发者|开发人员|运营者|创建者|所有者|超级用户|管理人员|root|admin)|我(就是|才是)(管理员|开发者|开发人员|你的主人)|以管理员身份)",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Chinesische Prompt-Injection erkannt.",
    ),
    (
        "Forget/Reset (ZH)",
        r"(忘记一切|清除记忆|重新开始|忘记(所有|全部|之前)(的)?(指令|对话|内容|记忆|信息)|清除(所有|全部)(的)?(记忆|上下文|对话|历史)|重置(你的)?(记忆|系统|状态|设定))",
        Severity.HIGH,
        "Prompt Injection",
        "BLOCKIEREN: Chinesische Prompt-Injection erkannt.",
    ),
    # --- v0.5.1: Broad Ignore/Disregard Patterns ---
    (
        "Broad Ignore Instructions (EN)",
        r"(?i)ignore\s+(the\s+|your\s+|my\s+)?(all\s+|any\s+|every\s+)?(previous|prior|above|below|further|earlier|last|first|initial|preceding|following|provided)?\s*(instructions?|directions?|rules?|prompts?|guidelines?|commands?|context|constraints?|and\s+(show|tell|give|reveal|print))",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK: Broad 'ignore instructions' pattern detected.",
    ),
    (
        "Disregard Instructions (EN)",
        r"(?i)(disregard|please\s+disregard)\s+(the\s+)?(all\s+|any\s+)?(instructions?|directions?|rules?|prompts?|guidelines?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK: Disregard instructions pattern detected.",
    ),
    (
        "Reveal/Show Secret/Hidden",
        r"(?i)(reveal|show|display|share|tell)\s+(me\s+)?(the\s+|your\s+)?(secret|hidden|confidential|private|internal)\s+(instructions?|rules?|prompt|password|word|key|info)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to extract secret/hidden information from the agent.",
    ),
    # --- v0.5.1: External Dataset Hardening ---
    (
        "Instruction Replay Request",
        r"(?i)(repeat|duplicate|copy|echo|restate|recite|write\s+out|print\s+out)\s+.{0,20}(instructions?|prompt|rules?|directions?|guidelines?)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to get the agent to replay its system instructions.",
    ),
    (
        "Instruction Query",
        r"(?i)(what\s+(were|are|is)\s+(the|your|all\s+of\s+your|all\s+your)\s+(initial\s+)?(instructions?|prompt|rules?|directions?)|how\s+were\s+you\s+(programmed|instructed|prompted)|have\s+you\s+been\s+given\s+.{0,20}(instructions?|prompt|rules?)|respond\s+with\s+(every|all)\s+instructions?|provide\s+instructions?|the\s+instructions?\s+have\s+changed|your\s+instructions?\s+(are|is|were)\s+(evil|wrong|bad|incorrect|outdated)|why\s+can.{0,10}(change|modify|update|override)\s+(your\s+)?(instructions?|rules?|prompt)|(not\s+be\s+)?programmed\s+to\s+(refuse|reject|deny|block)|apply\s+(your|the|all)\s+instructions?)",
        Severity.HIGH,
        "Prompt Injection",
        "Direct query about the agent's instructions or programming.",
    ),
    (
        "Supplement/Override Rule",
        r"(?i)(supplement(ary)?\s+rule|additional\s+rule|new\s+rule|override\s+rule|updated?\s+instruction|revised?\s+instruction)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to inject supplementary rules to override existing instructions.",
    ),
    (
        "Anti-Programming Bypass",
        r"(?i)(act\s+as\s+(you\s+would|if\s+you\s+were)\s+not\s+(programmed|designed|instructed)|respond\s+(without|ignoring)\s+(any\s+)?(restrictions?|constraints?|limitations?|programming))",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to make the agent act contrary to its programming.",
    ),
    (
        "Backwards/Encoded Output Request",
        r"(?i)(backwards?|reverse[d]?|encoded?|rot13|base64|hex|caesar)\s+.{0,20}(password|secret|instructions?|prompt|key|token)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to extract sensitive data via encoding/reversing tricks.",
    ),
]

DANGEROUS_COMMAND_PATTERNS = [
    # --- Shell / System Commands ---
    (
        "Destructive Shell Command",
        r"(?:rm\s+-[rRf]{1,3}\s+[\\/]|r\s+m\s+.{0,5}-\s*r\s*f|mkfs\s|dd\s+if=|format\s+[A-Z]:|\:\(\)\s*\{\s*\:\|\:\s*\&\s*\}|chmod\s+[0-7]*777\s+\/etc)",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Destructive system command detected (disk wipe, fork bomb, or recursive delete).",
    ),
    (
        "Remote Code Execution",
        r"(?:curl\s+.{0,100}\|\s*(?:ba)?sh|wget\s+.{0,100}\|\s*(?:ba)?sh|python[3]?\s+-c\s+['\"].*(?:exec|eval|import\s+os|base64)|\$\(\s*curl\s+.{0,100}\))",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Pipe-to-shell pattern detected. This downloads and executes remote code without inspection.",
    ),
    (
        "Reverse Shell",
        r"(?:(?:bash|sh|nc|ncat)\s+.{0,50}(?:\/dev\/tcp|mkfifo|nc\s+-[elp])|python[3]?\s+-c\s+['\"].*socket.*connect|nc\s+-[elp]\s+.{0,30}\d{2,5})",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Reverse shell pattern detected. An attacker is attempting to gain remote command access.",
    ),
    (
        "Sudoers Manipulation",
        r"(?:>>?\s*\/etc\/sudoers|visudo|NOPASSWD\s*:\s*ALL)",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Attempt to modify sudoers file for unauthorized privilege escalation.",
    ),
    (
        "Privilege Escalation",
        r"(?:sudo\s+(?:su|chmod\s+[0-7]*777|chown\s+root)|chmod\s+[0-7]*4[0-7]{3}\s|SUID|setuid)",
        Severity.HIGH,
        "Dangerous Command",
        "Privilege escalation attempt detected. The command tries to elevate system permissions.",
    ),
    (
        "Package / Dependency Install",
        r"(?:pip\s+install|npm\s+install|apt\s+install|yum\s+install|brew\s+install)\s+(?!--help)",
        Severity.MEDIUM,
        "Dangerous Command",
        "Software installation command detected. Verify the package source for supply-chain safety.",
    ),
]

# --- v0.2.0: Python Code Obfuscation Patterns ---
PYTHON_OBFUSCATION_PATTERNS = [
    (
        "Python getattr Obfuscation",
        r"(?:getattr\s*\(\s*\w+\s*,\s*['\"].+['\"]\s*\))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Python getattr() used to dynamically resolve functions. This is a common technique to bypass static code analysis (e.g., getattr(os, 'sys'+'tem')).",
    ),
    (
        "Python eval/exec",
        r"(?:(?:eval|exec|compile)\s*\(\s*(?:['\"]|[a-zA-Z_]))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Dynamic code execution via eval()/exec()/compile(). This can execute arbitrary obfuscated payloads.",
    ),
    (
        "Python __import__",
        r"(?:__import__\s*\(|importlib\.import_module\s*\()",
        Severity.HIGH,
        "Code Obfuscation",
        "Dynamic module import detected. Used to load dangerous modules (os, subprocess, socket) at runtime.",
    ),
    (
        "Python String Concatenation Bypass",
        r"(?:['\"][a-z]{1,6}['\"]\s*\+\s*['\"][a-z]{1,6}['\"])",
        Severity.MEDIUM,
        "Code Obfuscation",
        "String concatenation pattern detected (e.g., 'sys'+'tem'). Often used to evade keyword-based filters.",
    ),
    (
        "Python Dangerous File I/O",
        r"(?:open\s*\(\s*['\"]?\/(?:etc|proc|sys|dev|root|home|tmp|var|data)[\/'\"]|open\s*\(\s*['\"].*(?:shadow|passwd|id_rsa|authorized_keys|\.env|config|secret|token|key))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Python file read targeting sensitive system paths or credential files.",
    ),
    (
        "Python subprocess/os.system",
        r"(?:(?:subprocess|os)\s*\.\s*(?:system|popen|call|run|Popen|exec[lv]?[pe]?)\s*\(|(?:subprocess|os)\s*\[\s*['\"](?:system|popen|call|run)['\"])",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Direct OS command execution via Python subprocess/os module.",
    ),
    (
        "Python Socket Connection",
        r"(?:socket\.(?:socket|create_connection|connect)\s*\(|from\s+socket\s+import)",
        Severity.HIGH,
        "Code Obfuscation",
        "Network socket creation detected. Could be used for reverse shells or data exfiltration.",
    ),
    # --- v0.3.0: Ghost Exploit Defense ---
    (
        "Python Magic Attributes",
        r"(?:__builtins__|__globals__|__subclasses__|__class__|__bases__|__mro__|__dict__)",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Access to Python magic attributes detected. This is a reflection-based attack to bypass import restrictions and access dangerous builtins.",
    ),
    (
        "Python setattr/delattr Reflection",
        r"(?:(?:setattr|delattr)\s*\(\s*\w+\s*,\s*['\"])",
        Severity.HIGH,
        "Code Obfuscation",
        "Dynamic attribute manipulation via setattr/delattr. Can be used to inject malicious functions at runtime.",
    ),
    (
        "Suspicious open() in Agent Input",
        r"(?:open\s*\(\s*['\"]|open\s*\(\s*[a-zA-Z_]+\s*[,\)]|\['open'\]|\[\"open\"\])",
        Severity.HIGH,
        "Code Obfuscation",
        "File open() call detected in agent input. In an agent context, direct file operations are suspicious and should be reviewed.",
    ),
    (
        "Multi-Part String Assembly",
        r"(?:['\"][^'\"]{1,8}['\"]\s*\+\s*['\"][^'\"]{1,8}['\"]\s*\+\s*['\"][^'\"]{1,8}['\"])",
        Severity.HIGH,
        "Code Obfuscation",
        "Three or more short string fragments concatenated. Classic obfuscation technique to hide API keys, commands, or module names from static analysis.",
    ),
]

DATA_EXFILTRATION_PATTERNS = [
    # --- Secrets & API Keys ---
    (
        "Fragmented Secret Assembly",
        r"(?:(?:api[_-]?key|secret|token|password|key)\s*=\s*['\"][^'\"]{2,8}['\"]\s*\+\s*['\"])",
        Severity.HIGH,
        "Data Exfiltration",
        "API key or secret being assembled from string fragments to evade detection.",
    ),
    (
        "API Key Leak",
        r"(?:(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,})",
        Severity.CRITICAL,
        "Data Exfiltration",
        "CRITICAL: Hardcoded API key or access token found. This credential should be rotated immediately.",
    ),
    (
        "Private Key Material",
        r"(?:-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----)",
        Severity.CRITICAL,
        "Data Exfiltration",
        "CRITICAL: Private key material detected in text. This key is compromised and must be revoked.",
    ),
    (
        "Password in Cleartext",
        r"(?i)(?:password|passwort|passwd|kennwort|pwd)\s*[:=]\s*['\"]?[^\s'\"]{4,}",
        Severity.HIGH,
        "Data Exfiltration",
        "Cleartext password detected. Never store or transmit passwords in plain text.",
    ),
    (
        "Database Connection String",
        r"(?:(?:mongodb|postgres|mysql|redis|sqlite):\/\/[^\s]+|Data\s+Source=[^\s;]+)",
        Severity.HIGH,
        "Data Exfiltration",
        "Database connection string with potential credentials detected.",
    ),
    (
        "Email Harvesting Pattern",
        r"(?i)(?:forward|mail|email|send(?:en?)?)\s+.{0,40}?(?:to|an|nach)\s+[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
        Severity.MEDIUM,
        "Data Exfiltration",
        "Instruction to send data to an external email address. Verify recipient before proceeding.",
    ),
    (
        "Webhook Exfiltration",
        r"(?:(?:https?:\/\/)?(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|webhook\.site|requestbin|pipedream)\/[^\s]+)",
        Severity.HIGH,
        "Data Exfiltration",
        "Outbound webhook URL detected. Data may be exfiltrated to an external service.",
    ),
]

SOCIAL_ENGINEERING_PATTERNS = [
    (
        "Urgency Manipulation",
        r"(?i)(urgent|immediately|right\s+now|sofort|dringend|jetzt\s+sofort|without\s+delay|ohne\s+Verzögerung).{0,80}(send|execute|run|delete|pay|transfer|send(?:en?)?|ausführen|löschen|zahlen|überweisen)",
        Severity.MEDIUM,
        "Social Engineering",
        "Urgency + action pattern detected. Pressure tactics are a common social engineering technique.",
    ),
    (
        "Authority Impersonation",
        r"(?i)(i(?:'m|\s+am)\s+(your|the)\s+(admin|owner|creator|boss|CEO|supervisor|manager|system\s+administrator)|ich\s+bin\s+(dein|der)\s+(Admin|Besitzer|Ersteller|Chef|Vorgesetzter|Systemadministrator))",
        Severity.HIGH,
        "Social Engineering",
        "Authority impersonation detected. Verify the claimed identity through a separate channel.",
    ),
    (
        "Confidentiality Trap",
        r"(?i)(don't\s+tell|do\s+not\s+share|keep\s+this\s+(secret|private|between\s+us)|sag\s+(das\s+)?niemandem|behalte?\s+(das\s+)?für\s+dich)",
        Severity.MEDIUM,
        "Social Engineering",
        "Secrecy instruction detected. Legitimate requests don't require concealment from the system owner.",
    ),
    # --- v0.4.0: OWASP LLM Top 10 Expansion ---
    (
        "Approval Bypass (LLM08)",
        r"(?i)(don't\s+ask|don't\s+confirm|don't\s+verify|skip\s+(approval|confirmation|verification)|auto[_-]?(execute|approve|run)|ohne\s+R(?:ue|ü)ckfrage|ohne\s+Best(?:ae|ä)tigung|nicht\s+(fragen|nachfragen|best(?:ae|ä)tigen))",
        Severity.HIGH,
        "Social Engineering",
        "Attempt to bypass human approval for agent actions. OWASP LLM08: Excessive Agency risk.",
    ),
    (
        "Model Extraction (LLM10)",
        r"(?i)(export\s+(your|the)\s+(model|weights|parameters|architecture)|serialize\s+(your|the)\s+model|dump\s+(your|the)\s+(neural|model)|your\s+(architecture|training\s+data)\s+(is|are|was)|what\s+model\s+are\s+you|gib\s+mir\s+dein(e)?\s+(Modell|Gewichte|Architektur|Trainingsdaten))",
        Severity.HIGH,
        "Social Engineering",
        "Potential model extraction attempt. OWASP LLM10: Model Theft risk.",
    ),
    # --- v0.5.4: OWASP LLM04 — Model Denial of Service ---
    (
        "Repetition DoS (LLM04)",
        r"(?i)(repeat\s+(this|the|that|it|everything)\s+\d{2,}\s+times|write\s+\d{3,}\s+(words|lines|paragraphs|sentences)|generate\s+\d{3,}\s+(responses?|outputs?|completions?)|wiederhole?\s+(das|dies|alles)\s+\d{2,}\s+mal)",
        Severity.MEDIUM,
        "Prompt Injection",
        "Potential denial-of-service via forced repetition. OWASP LLM04: Model DoS.",
    ),
    (
        "Resource Exhaustion (LLM04)",
        r"(?i)(infinite\s+(loop|recursion|generation)|never\s+stop\s+(generating|writing|responding)|keep\s+going\s+forever|endlos\s+(generieren|schreiben|antworten)|h[oö]re?\s+nie(mals)?\s+auf)",
        Severity.MEDIUM,
        "Prompt Injection",
        "Attempt to force infinite generation. OWASP LLM04: Model DoS.",
    ),
    # --- v0.5.5: Real-World CVE Patterns ---
    (
        "Markdown Image Exfiltration",
        r"!\[[^\]]*\]\(https?://[^\s\)]+\?(q|data|d|secret|token|key|exfil|payload)=",
        Severity.CRITICAL,
        "Data Exfiltration",
        "Markdown image URL used to exfiltrate data via query parameter. Real-world vector: Bing Chat CVE, EchoLeak CVE-2025-32711.",
    ),
    (
        "Instruction Header Injection",
        r"(?i)(\*{2,}|#{2,}|={3,})\s*(IMPORTANT|CRITICAL|URGENT|NEW|UPDATED|SYSTEM)\s+(NEW\s+|UPDATED\s+)?(INSTRUCTIONS?|NOTICE|UPDATE|OVERRIDE|MESSAGE|RULES?|DIRECTIVES?)\s*(\*{2,}|#{2,}|={3,})?",
        Severity.CRITICAL,
        "Prompt Injection",
        "Formatted header attempting to inject authoritative instructions. Real-world vector: ChatGPT Cross-Plugin Request Forgery.",
    ),
    (
        "URL Data Exfiltration",
        r"(?i)(append|add|include|encode|concat|put)\s+.{0,30}(to|in|into|as)\s+(the\s+)?(url|link|href|query\s*string|parameter)",
        Severity.HIGH,
        "Data Exfiltration",
        "Attempt to exfiltrate data by encoding it into a URL. Real-world vector: Bing Chat, Slack AI data exfiltration.",
    ),
    (
        "Memory/Persistence Injection",
        r"(?i)(remember|memorize|store|save|persist|keep)\s+(this|that|the\s+following)\s+(for|in|across)\s+(all\s+)?(future|next|every|subsequent)\s+(conversations?|sessions?|interactions?|chats?)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to inject persistent instructions into AI memory. Real-world vector: ChatGPT SpAIware (Sep 2024).",
    ),
    (
        "Click-to-Authenticate Phishing",
        r"(?i)(click\s+here\s+to\s+(re)?authenticate|session\s+(has\s+)?expired?.{0,20}click|verify\s+your\s+(account|identity).{0,20}(click|link|url))",
        Severity.HIGH,
        "Social Engineering",
        "Phishing-style link disguised as authentication prompt. Real-world vector: Slack AI indirect injection.",
    ),
    (
        "Agent Impersonation",
        r"(?i)(message\s+from\s+(the\s+)?(admin|system|supervisor|orchestrat|research|finance|security|main)\s*[\-_]?\s*agent|as\s+the\s+(supervisor|admin|main|lead|master)\s+agent|from\s+(the\s+)?(admin|system)\s*[\-_]?\s*agent\s*:|agent\s+handoff.{0,20}(new\s+instructions?|override|ignore)|(disable|override|bypass)\s+(all\s+)?security\s+(checks?|filters?|constraints?|policies?))",
        Severity.CRITICAL,
        "Prompt Injection",
        "Agent-to-agent impersonation attempt. Attacker pretends to be a trusted agent in a multi-agent system. OWASP Agentic 2026.",
    ),
    (
        "Agent Goal Hijack (ASI01)",
        r"(?i)(your\s+new\s+(goal|objective|mission|purpose|task)\s+(is|should\s+be|will\s+be)|change\s+your\s+(goal|objective|mission|purpose)|redefine\s+your\s+(purpose|objective|mission))",
        Severity.CRITICAL,
        "Prompt Injection",
        "Attempt to hijack the agent's goal/objective. OWASP Agentic ASI01: Agent Goal Hijack.",
    ),
    (
        "Verification Bypass (ASI09)",
        r"(?i)(skip|bypass|ignore|disable|turn\s+off)\s+(all\s+)?(verification|validation|confirmation|approval|review|check)\s+(steps?|process|requirements?)?",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to skip safety verification. OWASP Agentic ASI09: Human-Agent Trust Exploitation.",
    ),
    (
        "Delegation Spoofing",
        r"(?i)(acting\s+on\s+behalf\s+of|authorized\s+by|delegated\s+by|sent\s+by|instructed\s+by|on\s+orders?\s+from|per\s+request\s+of|im\s+Auftrag\s+von|bevollm.chtigt\s+durch|beauftragt\s+von|au\s+nom\s+de|en\s+nombre\s+de|per\s+conto\s+di)\s+.{1,50}?(admin|system|ceo|cto|manager|direktor|supervisor|controller)",
        Severity.HIGH,
        "Social Engineering",
        "Delegation spoofing: Claims to act on behalf of authority figure. Adversa MCP TOP 25: Identity Spoofing.",
    ),
    (
        "Confused Deputy",
        r"(?i)(use\s+your\s+(admin|root|system|elevated|special)\s+(access|permissions?|privileges?|rights?)\s+(to|for|and)|since\s+you\s+have\s+(write|read|admin|root|execute|delete)\s+(access|permissions?)\s*[,.]|leverage\s+your\s+(credentials?|access|permissions?)\s+to|with\s+your\s+(elevated|admin|root|system)\s+(access|permissions?|privileges?)\s*[,.]|nutze?\s+(deine|Ihre)\s+(Admin|Root|System|erhoehten)\s*(Zugriff|Rechte|Berechtigungen)|utilise[rz]?\s+(vos|tes)\s+(droits|permissions?)\s+(admin|root|systeme))",
        Severity.HIGH,
        "Privilege Escalation",
        "Confused Deputy attack: Attempts to leverage the agent permissions for unauthorized actions. Adversa MCP TOP 25.",
    ),
    (
        "Tool Name Spoofing",
        r"(?i)(tool\s+(named?|called)\s+.{1,30}?(that\s+(actually|really|secretly)|but\s+(actually|really|instead))|register.*tool.*\s+(impersonat|pretend|disguise|mimic|spoof)|fake\s+tool\s+(registration|definition|metadata)|homoglyph|lookalike\s+tool|tool.{1,20}?(typosquat|name.?jack))",
        Severity.CRITICAL,
        "Tool Manipulation",
        "Tool name spoofing: Deceptive tool naming to impersonate trusted tools. Adversa MCP TOP 25.",
    ),
    (
        "Tool Shadowing",
        r"(?i)(register.*tool.{1,30}?(same|identical|duplicate|replace|override|overwrite)\s+(name|function|endpoint)|tool.{1,20}?(shadow|hijack|intercept|mitm|man.in.the.middle)|duplicate\s+tool\s+(registration|definition|name)|existing\s+tool.{1,20}?(replace|override|overwrite|shadow))",
        Severity.CRITICAL,
        "Tool Manipulation",
        "Tool shadowing: Attempt to override legitimate tool with malicious duplicate. CoSAI Threat #7.",
    ),
    (
        "Toxic Flow - Data Exfiltration Chain",
        r"(?i)(read.{1,30}?(then|and|before|after).{1,30}?(send|post|upload|transmit|exfiltrat)|fetch.{1,30}?(encode|encrypt|compress).{1,30}?(send|post|http|url|webhook)|extract.{1,30}?(data|content|secret|key|token).{1,30}?(forward|relay|pipe|redirect))",
        Severity.CRITICAL,
        "Data Exfiltration",
        "Toxic flow: Multi-step data exfiltration chain (read+encode+send). CoSAI Threat #8.",
    ),
    (
        "Toxic Flow - Privilege Chain",
        r"(?i)(first.{1,30}?(access|read|get).{1,30}?(then|next|after).{1,30}?(modify|write|delete|execute)|chain.{1,30}?(tool|function|api).{1,30}?(calls?|invocations?|requests?))",
        Severity.HIGH,
        "Privilege Escalation",
        "Toxic flow: Multi-step privilege escalation chain. CoSAI Threat #8.",
    ),
    (
        "Rug Pull - Tool Version Drift",
        r"(?i)(tool.{1,20}?(version|update|upgrade).{1,30}?(changed|modified|altered|different|unexpected)|previous(ly)?.{1,20}?(safe|trusted|verified).{1,20}?(now|suddenly|unexpected)|tool.{1,20}?(behavior|behaviour|function).{1,20}?(changed|different|altered)|rug.?pull|bait.{1,10}?(and|n).{1,10}?switch)",
        Severity.HIGH,
        "Tool Manipulation",
        "Rug pull: Tool behavior changed after initial trust was established. Adversa MCP TOP 25.",
    ),
    (
        "Tool Poisoning - Metadata Injection",
        r"(?i)(tool.{1,20}?(description|metadata|schema|manifest).{1,30}?(hidden|inject|embed|conceal)|hidden.{1,20}?(instruction|command|directive).{1,20}?(in|inside|within).{1,20}?(description|metadata|schema)|metadata.{1,20}?(poison|inject|tamper|manipulat))",
        Severity.CRITICAL,
        "Tool Manipulation",
        "Tool poisoning via metadata injection. Hidden instructions in tool descriptions. Adversa MCP TOP 25.",
    ),
    (
        "Tool Poisoning - Return Value Manipulation",
        r"(?i)(tool.{1,20}?(return|output|response).{1,30}?(inject|embed|append|prepend|modify).{1,30}?(instruction|command|prompt)|manipulat.{1,20}?(tool|function|api).{1,20}?(output|return|response)|poison.{1,20}?(return|output|result))",
        Severity.CRITICAL,
        "Tool Manipulation",
        "Tool poisoning via return value manipulation. Malicious instructions injected in tool output. Adversa MCP TOP 25.",
    ),
    # --- v0.6.1: OWASP Agentic ASI07 — Insecure Inter-Agent Communication ---
    (
        "Inter-Agent Instruction Relay (ASI07)",
        r"(?i)(forward|relay|pass|send|transmit|propagate)\s+(this|these|the\s+following)?\s*(instructions?|commands?|directives?|messages?|prompts?)\s+(to|for|at)\s+(the\s+)?(other|next|downstream|receiving|target|secondary)\s+(agent|model|assistant|llm|service)",
        Severity.HIGH,
        "Inter-Agent Security",
        "Inter-agent instruction relay: Attempt to inject commands via agent-to-agent communication. OWASP Agentic ASI07.",
    ),
    (
        "Cross-Agent Prompt Injection (ASI07)",
        r"(?i)(when\s+(the\s+)?(next|other|downstream|target)\s+(agent|model|assistant)\s+(calls?|contacts?|queries?|asks?)|include\s+this\s+in\s+your\s+(response|output|reply)\s+to\s+(the\s+)?(other|next|calling|requesting)\s+(agent|model|service)|prepare\s+(this|these|the\s+following)\s+(payload|instructions?|commands?)\s+for\s+(the\s+)?(next|downstream|receiving)\s+(agent|model))",
        Severity.CRITICAL,
        "Inter-Agent Security",
        "Cross-agent prompt injection: Planting instructions for downstream agents. OWASP Agentic ASI07.",
    ),
    (
        "Unvalidated Agent Delegation (ASI07)",
        r"(?i)(agent.{1,20}?(delegate|transfer|hand\s*off|route|redirect).{1,30}?(to|for)\s+(another|different|external|untrusted)|without\s+(authenticat|validat|verif).{1,30}?agent.{1,20}?(communicat|message|request)|bypass.{1,20}?(agent|inter.?agent)\s+(auth|validat|verif)|unvalidated.{1,20}?(delegation|handoff|transfer)\s+(chain|request))",
        Severity.HIGH,
        "Inter-Agent Security",
        "Unvalidated agent delegation: Agent communication without proper authentication. OWASP Agentic ASI07.",
    ),
    (
        "Arabic Prompt Injection",
        r"(تجاهل|تخطى|أهمل|ألغِ|تجاوز).{0,30}?(التعليمات|الأوامر|القواعد|النظام)",
        Severity.CRITICAL,
        "Prompt Injection",
        "Arabic prompt injection: Ignore/bypass instructions pattern. Multilingual coverage.",
    ),
    (
        "Hindi Prompt Injection",
        r"(अनदेखा|नज़रअंदाज़|पिछले|निर्देश).{0,30}?(निर्देश|नियम|आदेश|हदायत)",
        Severity.CRITICAL,
        "Prompt Injection",
        "Hindi prompt injection: Ignore/bypass instructions pattern. Multilingual coverage.",
    ),
    (
        "Arabic Role Override",
        r"(أنتِ?\s+الآن|دورك\s+الجديد|تصرف\s+ك|أنت\s+عبارة\s+عن)",
        Severity.HIGH,
        "Prompt Injection",
        "Arabic role/identity override attempt. Multilingual coverage.",
    ),
    (
        "Hindi Role Override",
        r"(तुम\s+अब|तुम्हारा\s+नया\s+काम|अपनी\s+भूमिका\s+बदलो|तुम\s+एक\s+.{1,20}?हो)",
        Severity.HIGH,
        "Prompt Injection",
        "Hindi role/identity override attempt. Multilingual coverage.",
    ),
    (
        "System Controller Impersonation",
        r"(?i)(this\s+(message|instruction|command|request)\s+(is\s+|was\s+)?(from|by)\s+(the\s+)?(system|central|master)\s*(controller|manager|orchestrator|coordinator)|diese\s+(Nachricht|Anweisung)\s+(kommt\s+)?(vom|aus\s+dem)\s+(System|Zentral)\s*(controller|steuerung))",
        Severity.CRITICAL,
        "Prompt Injection",
        "System controller impersonation. Fake authority claim. Adversa MCP TOP 25: Identity Spoofing.",
    ),
]

# --- v0.4.0: OWASP LLM02/LLM04 Patterns ---
OUTPUT_INJECTION_PATTERNS = [
    (
        "HTML/JS Injection (LLM02)",
        r"(?:<script[\s>]|javascript\s*:|onerror\s*=|onload\s*=|onclick\s*=|<iframe[\s>]|<object[\s>]|<embed[\s>]|<svg[\s>].*?on\w+\s*=)",
        Severity.HIGH,
        "Output Injection",
        "HTML/JavaScript injection pattern in output. OWASP LLM02: Insecure Output Handling.",
    ),
    (
        "SQL Injection Fragment (LLM02)",
        r"(?i)(?:'\s*(?:OR|AND)\s+['\d]|UNION\s+(?:ALL\s+)?SELECT|INSERT\s+INTO|DROP\s+TABLE|DELETE\s+FROM|UPDATE\s+\w+\s+SET|;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER)\s)",
        Severity.HIGH,
        "Output Injection",
        "SQL injection fragment detected. OWASP LLM02: Insecure Output Handling.",
    ),
]

PII_DETECTION_PATTERNS = [
    (
        "German IBAN (LLM06)",
        r"(?:DE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2})",
        Severity.HIGH,
        "Data Exfiltration",
        "German IBAN detected. OWASP LLM06: Sensitive Information Disclosure.",
    ),
    (
        "Credit Card Number (LLM06)",
        r"(?:\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b)",
        Severity.CRITICAL,
        "Data Exfiltration",
        "Credit card number pattern detected. OWASP LLM06: Sensitive Information Disclosure.",
    ),
    (
        "German Phone Number (LLM06)",
        r"(?:(?:\+49|0049|0)\s?(?:\(?\d{2,5}\)?\s?)[\d\s/\-]{6,12}\d)",
        Severity.MEDIUM,
        "Data Exfiltration",
        "German phone number detected. OWASP LLM06: Sensitive Information Disclosure.",
    ),
]

ALL_PATTERNS = (
    PROMPT_INJECTION_PATTERNS
    + DANGEROUS_COMMAND_PATTERNS
    + PYTHON_OBFUSCATION_PATTERNS
    + DATA_EXFILTRATION_PATTERNS
    + SOCIAL_ENGINEERING_PATTERNS
    + OUTPUT_INJECTION_PATTERNS
    + PII_DETECTION_PATTERNS
)

# ─── Compiled Pattern Cache (performance: ~30% faster on repeated scans) ─────
COMPILED_PATTERNS = [
    (name, re.compile(pattern), severity, category, recommendation)
    for name, pattern, severity, category, recommendation in ALL_PATTERNS
]


# ─── Preprocessor: Evasion Normalization ─────────────────────────────────────

LEET_MAP = str.maketrans("013457@!", "oieastal")

# Zero-width characters used for evasion
ZERO_WIDTH_CHARS = str.maketrans('', '', '\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064')

# Unicode homoglyphs (common Cyrillic/Greek lookalikes)
HOMOGLYPH_MAP = str.maketrans({
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0443': 'y',  # Cyrillic у
    '\u0456': 'i',  # Cyrillic і
    '\u0445': 'x',  # Cyrillic х
    '\u0410': 'A',  # Cyrillic А
    '\u0415': 'E',  # Cyrillic Е
    '\u041e': 'O',  # Cyrillic О
    '\u0421': 'C',  # Cyrillic С
    '\u0422': 'T',  # Cyrillic Т
})


def _strip_zero_width(text: str) -> str:
    """Remove zero-width characters used to evade pattern matching."""
    return text.translate(ZERO_WIDTH_CHARS)


def _normalize_homoglyphs(text: str) -> str:
    """Replace Unicode homoglyphs (Cyrillic/Greek lookalikes) with ASCII."""
    return text.translate(HOMOGLYPH_MAP)


def _normalize_fullwidth(text: str) -> str:
    """Convert fullwidth Unicode characters to ASCII equivalents."""
    import unicodedata
    result = []
    for c in text:
        nfkd = unicodedata.normalize("NFKC", c)
        result.append(nfkd)
    return "".join(result)


def _strip_null_bytes(text: str) -> str:
    """Remove null bytes, control characters, and invisible formatters used for evasion."""
    return text.translate({
        0x00: None,   # Null byte
        0x08: None,   # Backspace
        0xAD: None,   # Soft hyphen
        0xFEFF: None, # BOM / zero-width no-break space
        0x2060: None, # Word joiner
        0x2061: None, # Function application
        0x2062: None, # Invisible times
        0x2063: None, # Invisible separator
        0x2064: None, # Invisible plus
        0xFFF9: None, # Interlinear annotation anchor
        0xFFFA: None, # Interlinear annotation separator
        0xFFFB: None, # Interlinear annotation terminator
    })


def _decode_base64_fragments(text: str) -> str:
    """Detect and decode inline Base64 fragments that look like encoded commands."""
    import base64
    def _try_decode(match):
        try:
            decoded = base64.b64decode(match.group(0)).decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 3:
                return match.group(0) + ' ' + decoded
        except Exception:
            pass
        return match.group(0)
    # Look for Base64-like strings (20+ chars, valid charset)
    return re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', _try_decode, text)


def _normalize_leet(text: str) -> str:
    """Convert common leetspeak substitutions back to letters."""
    return text.translate(LEET_MAP)

def _collapse_spaces(text: str) -> str:
    """Detect and collapse spaced-out evasion (e.g. 'I G N O R E' -> 'IGNORE').
    Finds runs of single non-space chars separated by 1-3 spaces (min 3 chars),
    collapses them, and re-joins with single space between collapsed words."""
    import re as _re
    # Split on double-or-more spaces to find word groups, then collapse within each
    def _collapse_run(segment):
        # If segment looks like spaced-out chars (single chars separated by spaces)
        chars = segment.split(' ')
        if len(chars) >= 3 and all(len(c) <= 1 for c in chars if c):
            return ''.join(c for c in chars if c)
        return segment
    # Split on double+ spaces to separate "words"
    parts = _re.split(r'\s{2,}', text)
    collapsed_parts = [_collapse_run(p) for p in parts]
    return ' '.join(collapsed_parts)


# ─── Scanner Engine ──────────────────────────────────────────────────────────

def scan_text(text: str, source: str = "stdin") -> ScanReport:
    """Scan a block of text against all security patterns."""
    lines = text.splitlines()
    report = ScanReport(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        source=source,
        total_lines=len(lines),
    )

    for line_num, line in enumerate(lines, start=1):
        # Generate normalized variants for evasion detection
        line_variants = [line]
        # Strip zero-width characters
        stripped = _strip_zero_width(line)
        if stripped != line:
            line_variants.append(stripped)
        # Normalize homoglyphs (Cyrillic/Greek lookalikes)
        dehomoglyph = _normalize_homoglyphs(stripped if stripped != line else line)
        if dehomoglyph not in line_variants:
            line_variants.append(dehomoglyph)
        # Leetspeak normalization
        normalized = _normalize_leet(dehomoglyph)
        if normalized not in line_variants:
            line_variants.append(normalized)
        # Space-collapse
        collapsed = _collapse_spaces(line)
        if collapsed not in line_variants:
            line_variants.append(collapsed)
        # Base64 decode attempt
        decoded = _decode_base64_fragments(line)
        if decoded != line and decoded not in line_variants:
            line_variants.append(decoded)
        # Fullwidth Unicode normalization
        fullwidth = _normalize_fullwidth(line)
        if fullwidth != line and fullwidth not in line_variants:
            line_variants.append(fullwidth)
        # Null-byte / control-char stripping
        nullfree = _strip_null_bytes(line)
        if nullfree != line and nullfree not in line_variants:
            line_variants.append(nullfree)

        for name, compiled, severity, category, recommendation in COMPILED_PATTERNS:
            matched_any = False
            for variant in line_variants:
                if matched_any:
                    break
                for match in compiled.finditer(variant):
                    matched_any = True
                    matched = match.group(0)
                    # Build context: show a snippet around the match (use original line)
                    start = max(0, match.start() - 30)
                    end = min(len(line), match.end() + 30)
                    context = ("..." if start > 0 else "") + line[start:end] + ("..." if end < len(line) else "")

                    report.findings.append(Finding(
                        severity=severity,
                        category=category,
                        pattern_name=name,
                        matched_text=matched[:120],
                        line_number=line_num,
                        context=context.strip(),
                        recommendation=recommendation,
                    ))

    # Deduplicate findings (same pattern on the same line)
    seen = set()
    unique_findings = []
    for f in report.findings:
        key = (f.pattern_name, f.line_number, f.matched_text)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    report.findings = unique_findings
    report.total_findings = len(report.findings)

    # Confidence scoring
    _CONF_BASE = {"CRITICAL": 90, "HIGH": 80, "MEDIUM": 65, "LOW": 50}
    line_finding_count = {}
    for f in report.findings:
        line_finding_count[f.line_number] = line_finding_count.get(f.line_number, 0) + 1

    for f in report.findings:
        conf = _CONF_BASE[f.severity.value]
        if line_finding_count[f.line_number] > 1:
            conf += 10
        if len(f.matched_text) > 20:
            conf += 5
        if len(f.matched_text) < 5:
            conf -= 10
        src_line = lines[f.line_number - 1].lstrip() if f.line_number <= len(lines) else ""
        if src_line.startswith("#") or src_line.startswith("//") or src_line.startswith("--"):
            conf -= 15
        f.confidence = max(10, min(99, conf))

    # Calculate risk score (0-10 scale)
    raw = sum(f.severity.score() for f in report.findings)
    report.risk_score = min(10, raw)

    # Determine risk level
    if report.risk_score == 0:
        report.risk_level = "CLEAN"
    elif report.risk_score <= 3:
        report.risk_level = "LOW"
    elif report.risk_score <= 6:
        report.risk_level = "MEDIUM"
    elif report.risk_score <= 8:
        report.risk_level = "HIGH"
    else:
        report.risk_level = "CRITICAL"

    return report


# ─── Output Formatters ───────────────────────────────────────────────────────

SEVERITY_ICONS = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}

RISK_ICONS = {
    "CLEAN": "✅",
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}


def format_human(report: ScanReport) -> str:
    """Format the report for human-readable terminal output."""
    icon = RISK_ICONS.get(report.risk_level, "❓")
    lines = [
        "",
        "═" * 64,
        f"  🛡️  ClawGuard v0.3.0 – Security Scan Report",
        "═" * 64,
        f"  Timestamp : {report.timestamp}",
        f"  Source    : {report.source}",
        f"  Lines     : {report.total_lines}",
        f"  Findings  : {report.total_findings}",
        f"  Risk Score: {report.risk_score}/10  {icon} {report.risk_level}",
        "─" * 64,
    ]

    if not report.findings:
        lines.append("  ✅ No threats detected. Input appears safe.")
    else:
        for i, f in enumerate(report.findings, start=1):
            sev_icon = SEVERITY_ICONS.get(f.severity.value, "❓")
            lines.append(f"\n  [{i}] {sev_icon} {f.severity.value} ({f.confidence}%) – {f.pattern_name}")
            lines.append(f"      Category : {f.category}")
            lines.append(f"      Line     : {f.line_number}")
            lines.append(f"      Match    : \"{f.matched_text}\"")
            lines.append(f"      Context  : {f.context}")
            lines.append(f"      Action   : {f.recommendation}")

    lines.append("")
    lines.append("═" * 64)

    if report.risk_score >= 7:
        lines.append("  ⛔ RECOMMENDATION: BLOCK this input. Do NOT forward to agent.")
    elif report.risk_score >= 4:
        lines.append("  ⚠️  RECOMMENDATION: Review manually before forwarding.")
    elif report.risk_score >= 1:
        lines.append("  ℹ️  RECOMMENDATION: Low risk. Monitor but likely safe.")
    else:
        lines.append("  ✅ RECOMMENDATION: Input is clean. Safe to process.")

    lines.append("═" * 64)
    lines.append("")
    return "\n".join(lines)


def format_json(report: ScanReport) -> str:
    """Format the report as machine-readable JSON."""
    data = {
        "clawguard_version": "0.3.0",
        "timestamp": report.timestamp,
        "source": report.source,
        "total_lines": report.total_lines,
        "total_findings": report.total_findings,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "findings": [
            {
                "severity": f.severity.value,
                "category": f.category,
                "pattern_name": f.pattern_name,
                "matched_text": f.matched_text,
                "line_number": f.line_number,
                "context": f.context,
                "recommendation": f.recommendation,
                "confidence": f.confidence,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    # Fix emoji output on Windows (cp1252 can't encode Unicode symbols)
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="🛡️  ClawGuard – The Firewall for Autonomous AI Agents",
        epilog="(c) 2026 Jörg Michno. Zero dependencies. Zero cost. Maximum security.",
    )
    parser.add_argument("file", nargs="?", help="Text file to scan")
    parser.add_argument("--stdin", action="store_true", help="Read from standard input")
    parser.add_argument("--json", action="store_true", help="Output report as JSON (for automation)")
    parser.add_argument("--version", action="version", version="ClawGuard v0.3.0")

    args = parser.parse_args()

    # Determine input source
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            source = args.file
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(2)
        except PermissionError:
            print(f"Error: Permission denied: {args.file}", file=sys.stderr)
            sys.exit(2)
    elif args.stdin or not sys.stdin.isatty():
        text = sys.stdin.read()
        source = "stdin"
    else:
        parser.print_help()
        sys.exit(2)

    # Run the scan
    report = scan_text(text, source=source)

    # Output the report
    if args.json:
        print(format_json(report))
    else:
        print(format_human(report))

    # Exit code: 0 = clean, 1 = threats found
    sys.exit(0 if report.total_findings == 0 else 1)


if __name__ == "__main__":
    main()
