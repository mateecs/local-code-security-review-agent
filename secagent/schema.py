from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Candidate:
    """A lead produced by a deterministic tool (rules, secrets scan, bandit...)."""
    file: str
    line: int
    rule_id: str
    cwe: str
    severity: str
    message: str
    snippet: str = ""
    tool: str = "rules"


@dataclass
class Finding:
    title: str
    file: str
    line: int
    severity: str = "medium"
    cwe: str = ""
    evidence: str = ""
    explanation: str = ""
    remediation: str = ""
    confidence: float = 0.5
    source: str = "llm"                 # llm | static | both
    verified: bool | None = None        # evidence located in the file?
    verification: str = ""
    kb_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cwe_id"] = cwe_id(self)
        return d


REMEDIATION = {
    "CWE-89": "Use parameterized queries / prepared statements; never concatenate user input into SQL.",
    "CWE-79": "Escape output for its HTML context (auto-escaping templates); avoid render_template_string/Markup with user input.",
    "CWE-22": "Resolve paths against a fixed base directory (safe_join / secure_filename) and reject anything that escapes it.",
    "CWE-78": "Avoid shells: pass an argument list to subprocess (no shell=True) and validate input against an allow-list.",
    "CWE-95": "Do not eval/exec dynamic input; use safe parsers such as ast.literal_eval or json.",
    "CWE-502": "Never deserialize untrusted data with pickle/yaml.load; use JSON or yaml.safe_load.",
    "CWE-327": "Use SHA-256+ for integrity and bcrypt/scrypt/argon2 (or PBKDF2) for password storage.",
    "CWE-798": "Move secrets to environment variables or a secret manager, and rotate the exposed value.",
    "CWE-489": "Disable debug mode outside development and bind only to the interfaces you need.",
    "CWE-295": "Keep TLS verification enabled; configure a trusted CA bundle instead of disabling checks.",
    "CWE-306": "Require authentication and server-side authorization on sensitive routes (decorator/middleware).",
    "CWE-338": "Use the 'secrets' module for tokens, passwords and one-time codes.",
    "CWE-347": "Always verify JWT signatures and pin the accepted algorithms.",
    "CWE-942": "Use an explicit allow-list of trusted origins.",
    "CWE-918": "Validate/allow-list outbound URLs and block internal address ranges.",
    "CWE-1427": "Treat code under review as data. This text may be trying to manipulate AI tooling: review the file manually.",
    "CWE-1104": "Pin dependency versions and audit them regularly (e.g. pip-audit).",
}

CWE_GROUPS = [
    {"287", "306", "862", "863", "284"},
    {"798", "259", "321", "547"},
    {"89", "564"},
    {"78", "77"},
    {"94", "95", "96"},
    {"327", "328", "326", "916", "759", "760"},
    {"489", "215", "16", "1188", "11", "209"},
    {"22", "23", "36", "73"},
    {"79", "80", "83"},
    {"295", "297"},
    {"338", "330", "331", "340"},
]

TITLE_TO_CWE = [
    (r"sql\s*inj|sqli", "89"), (r"cross.?site script|\bxss\b", "79"),
    (r"path traversal|directory traversal", "22"), (r"command inj|os command|shell inj", "78"),
    (r"hard.?coded|embedded (secret|credential|key)|exposed (secret|key)", "798"),
    (r"deserializ", "502"), (r"weak (hash|crypto)|md5|sha-?1", "327"),
    (r"missing auth|no auth|improper auth|authenticat", "306"), (r"debug", "489"),
    (r"ssrf|server.?side request", "918"), (r"certificate|tls verif|ssl verif", "295"),
    (r"eval|code inj", "95"), (r"prompt inj", "1427"),
]


def normalize_severity(value: str) -> str:
    v = str(value or "").strip().lower()
    return v if v in SEV_RANK else {"warning": "medium", "error": "high", "moderate": "medium"}.get(v, "medium")


def cwe_id(f: "Finding | Candidate") -> str:
    """Numeric CWE id as a string ('' if unknown). Falls back to keywords in the title."""
    m = re.search(r"(\d{2,4})", f.cwe or "")
    if m:
        return m.group(1)
    text = (getattr(f, "title", "") or getattr(f, "message", "")).lower()
    for pattern, num in TITLE_TO_CWE:
        if re.search(pattern, text):
            return num
    return ""


def cwe_group(num: str) -> frozenset:
    for g in CWE_GROUPS:
        if num in g:
            return frozenset(g)
    return frozenset({num}) if num else frozenset()


def same_weakness(a: str, b: str) -> bool:
    """True if two CWE ids are equal or in the same family. Unknown ids are compatible."""
    if not a or not b:
        return True
    return b in cwe_group(a)


def candidate_to_finding(c: Candidate) -> Finding:
    prior = {"critical": 0.7, "high": 0.6, "medium": 0.5, "low": 0.4, "info": 0.3}.get(c.severity, 0.5)
    return Finding(
        title=c.message, file=c.file, line=c.line, severity=c.severity, cwe=c.cwe,
        evidence=c.snippet, explanation=f"[{c.tool}:{c.rule_id}] {c.message}",
        remediation=REMEDIATION.get(c.cwe, ""), confidence=prior, source="static",
    )
